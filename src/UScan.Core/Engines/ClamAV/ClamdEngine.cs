using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using UScan.Core.Model;

namespace UScan.Core.Engines.ClamAV;

public sealed class ClamdOptions
{
    public string Host { get; init; } = "127.0.0.1";
    public int Port { get; init; } = 3310;
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Upper bound for one complete INSTREAM exchange, including clamd's scan time.</summary>
    public TimeSpan ScanTimeout { get; init; } = TimeSpan.FromMinutes(5);

    public int ChunkSize { get; init; } = 64 * 1024;

    /// <summary>Must not exceed StreamMaxLength in clamd.conf. Larger files are skipped and labelled as such.</summary>
    public long MaxStreamBytes { get; init; } = 100L * 1024 * 1024;

    /// <summary>
    /// File contents are sent to clamd. By default only loopback addresses are accepted so
    /// that no file content ever leaves the machine unintentionally.
    /// </summary>
    public bool AllowNonLoopbackHost { get; init; }
}

/// <summary>
/// Client for a local clamd daemon over TCP using the documented INSTREAM protocol.
/// clamd runs as a separate process, so a parser crash inside libclamav cannot take
/// down the UScan process, and UScan does not link GPL code.
/// </summary>
public sealed class ClamdEngine : IScanEngine
{
    private readonly ClamdOptions _options;

    public ClamdEngine(ClamdOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.ChunkSize is < 1024 or > 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "ChunkSize must be between 1 KiB and 1 MiB.");
        }

        if (!options.AllowNonLoopbackHost && !IsLoopback(options.Host))
        {
            throw new ArgumentException(
                $"clamd host '{options.Host}' is not a loopback address. Set AllowNonLoopbackHost explicitly to send file contents to another machine.",
                nameof(options));
        }

        _options = options;
    }

    public string Id => ClamdResponseParser.EngineId;

    public long MaxStreamBytes => _options.MaxStreamBytes;

    public async Task<bool> PingAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await SimpleCommandAsync("PING", cancellationToken).ConfigureAwait(false) == "PONG";
        }
        catch (EngineUnavailableException)
        {
            return false;
        }
    }

    public async Task<EngineInfo> GetInfoAsync(CancellationToken cancellationToken)
    {
        var reply = await SimpleCommandAsync("VERSION", cancellationToken).ConfigureAwait(false);
        return ClamdResponseParser.ParseVersion(reply);
    }

    public async Task<EngineResult> ScanAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.ScanTimeout);
        var ct = timeout.Token;

        using var client = await ConnectAsync(ct).ConfigureAwait(false);
        var net = client.GetStream();

        var buffer = ArrayPool<byte>.Shared.Rent(_options.ChunkSize + 4);
        try
        {
            await net.WriteAsync("zINSTREAM\0"u8.ToArray(), ct).ConfigureAwait(false);

            long total = 0;
            bool sendFailed = false;
            while (true)
            {
                var read = await content.ReadAsync(buffer.AsMemory(4, _options.ChunkSize), ct).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > _options.MaxStreamBytes)
                {
                    // The caller is expected to pre-check sizes; this guards against files growing during the scan.
                    return new EngineResult(Verdict.Skipped, Id, null, $"Stream exceeded {_options.MaxStreamBytes} bytes while scanning.");
                }

                BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), (uint)read);
                try
                {
                    await net.WriteAsync(buffer.AsMemory(0, read + 4), ct).ConfigureAwait(false);
                }
                catch (IOException)
                {
                    // clamd closes the socket early when its own StreamMaxLength is hit; its reply is still readable.
                    sendFailed = true;
                    break;
                }
            }

            if (!sendFailed)
            {
                BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), 0);
                await net.WriteAsync(buffer.AsMemory(0, 4), ct).ConfigureAwait(false);
            }

            var reply = await ReadReplyAsync(net, ct).ConfigureAwait(false);
            if (sendFailed && reply.Length == 0)
            {
                throw new EngineUnavailableException("clamd closed the connection during INSTREAM without a reply.");
            }

            return ClamdResponseParser.ParseScanReply(reply);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new EngineResult(Verdict.Error, Id, null, $"clamd did not answer within {_options.ScanTimeout}.");
        }
        catch (SocketException ex)
        {
            throw new EngineUnavailableException($"Connection to clamd failed: {ex.Message}", ex);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task<string> SimpleCommandAsync(string command, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.ConnectTimeout * 2);
        try
        {
            using var client = await ConnectAsync(timeout.Token).ConfigureAwait(false);
            var net = client.GetStream();
            await net.WriteAsync(Encoding.ASCII.GetBytes($"z{command}\0"), timeout.Token).ConfigureAwait(false);
            return (await ReadReplyAsync(net, timeout.Token).ConfigureAwait(false)).TrimEnd('\0', '\n');
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new EngineUnavailableException($"clamd did not answer '{command}' in time.");
        }
        catch (IOException ex)
        {
            throw new EngineUnavailableException($"clamd connection failed during '{command}': {ex.Message}", ex);
        }
    }

    private async Task<TcpClient> ConnectAsync(CancellationToken cancellationToken)
    {
        var client = new TcpClient { NoDelay = true };
        using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectTimeout.CancelAfter(_options.ConnectTimeout);
        try
        {
            await client.ConnectAsync(_options.Host, _options.Port, connectTimeout.Token).ConfigureAwait(false);
            return client;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            client.Dispose();
            throw new EngineUnavailableException($"clamd is not reachable at {_options.Host}:{_options.Port}: {ex.Message}", ex);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    /// <summary>Reads until the terminating NUL (z-commands) or EOF. Replies are short; cap at 4 KiB.</summary>
    private static async Task<string> ReadReplyAsync(NetworkStream net, CancellationToken cancellationToken)
    {
        const int MaxReply = 4096;
        var buffer = new byte[MaxReply];
        var length = 0;
        while (length < MaxReply)
        {
            int read;
            try
            {
                read = await net.ReadAsync(buffer.AsMemory(length, MaxReply - length), cancellationToken).ConfigureAwait(false);
            }
            catch (IOException) when (length > 0)
            {
                break;
            }

            if (read == 0)
            {
                break;
            }

            var nul = Array.IndexOf(buffer, (byte)0, length, read);
            length += read;
            if (nul >= 0)
            {
                length = nul;
                break;
            }
        }

        return Encoding.UTF8.GetString(buffer, 0, length);
    }

    private static bool IsLoopback(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
        || (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip));
}
