using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using UScan.Core.Engines;
using UScan.Core.Engines.ClamAV;
using UScan.Core.Model;

namespace UScan.Core.Tests.Unit;

/// <summary>Exercises the INSTREAM wire format and failure handling against a scripted fake daemon.</summary>
public class ClamdProtocolTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Instream_frames_are_length_prefixed_and_terminated()
    {
        var data = new byte[200_000];
        Random.Shared.NextBytes(data);
        byte[]? received = null;
        string? command = null;

        await using var server = FakeDaemon.Start(async s =>
        {
            command = await ReadCommand(s);
            using var ms = new MemoryStream();
            var len = new byte[4];
            while (true)
            {
                await s.ReadExactlyAsync(len);
                var n = BinaryPrimitives.ReadUInt32BigEndian(len);
                if (n == 0)
                {
                    break;
                }

                Assert.True(n <= 4096, "chunk larger than configured ChunkSize");
                var chunk = new byte[n];
                await s.ReadExactlyAsync(chunk);
                ms.Write(chunk);
            }

            received = ms.ToArray();
            await s.WriteAsync("stream: OK\0"u8.ToArray());
        });

        var engine = new ClamdEngine(new ClamdOptions { Port = server.Port, ChunkSize = 4096 });
        var result = await engine.ScanAsync(new MemoryStream(data), Ct);

        Assert.Equal("zINSTREAM", command);
        Assert.Equal(Verdict.Clean, result.Verdict);
        Assert.Equal(data, received);
    }

    [Fact]
    public async Task Daemon_that_closes_early_with_size_error_yields_error_not_clean()
    {
        await using var server = FakeDaemon.Start(async s =>
        {
            await ReadCommand(s);
            var buf = new byte[8192];
            _ = await s.ReadAsync(buf);
            await s.WriteAsync("INSTREAM size limit exceeded. ERROR\0"u8.ToArray());
            s.Socket.Shutdown(SocketShutdown.Both);
        });

        var engine = new ClamdEngine(new ClamdOptions { Port = server.Port, ChunkSize = 4096 });
        var result = await engine.ScanAsync(new MemoryStream(new byte[2_000_000]), Ct);

        Assert.Equal(Verdict.Error, result.Verdict);
    }

    [Fact]
    public async Task Silent_daemon_times_out_as_error()
    {
        await using var server = FakeDaemon.Start(async s => await Task.Delay(Timeout.Infinite, s.Token));

        var engine = new ClamdEngine(new ClamdOptions { Port = server.Port, ScanTimeout = TimeSpan.FromMilliseconds(500) });
        var result = await engine.ScanAsync(new MemoryStream([1, 2, 3]), Ct);

        Assert.Equal(Verdict.Error, result.Verdict);
        Assert.Contains("did not answer", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unreachable_daemon_throws_engine_unavailable()
    {
        var port = FakeDaemon.FreePort();
        var engine = new ClamdEngine(new ClamdOptions { Port = port, ConnectTimeout = TimeSpan.FromSeconds(1) });

        await Assert.ThrowsAsync<EngineUnavailableException>(() => engine.ScanAsync(new MemoryStream([1]), Ct));
        await Assert.ThrowsAsync<EngineUnavailableException>(() => engine.GetInfoAsync(Ct));
        Assert.False(await engine.PingAsync(Ct));
    }

    [Theory]
    [InlineData("10.0.0.5")]
    [InlineData("example.com")]
    [InlineData("0.0.0.0")]
    public void Non_loopback_host_is_rejected_by_default(string host) =>
        Assert.Throws<ArgumentException>(() => new ClamdEngine(new ClamdOptions { Host = host }));

    [Fact]
    public void Non_loopback_host_requires_explicit_opt_in()
    {
        var e = new ClamdEngine(new ClamdOptions { Host = "10.0.0.5", AllowNonLoopbackHost = true });
        Assert.Equal("clamav", e.Id);
    }

    [Fact]
    public async Task Oversized_reply_is_truncated_safely()
    {
        await using var server = FakeDaemon.Start(async s =>
        {
            await ReadCommand(s);
            await s.WriteAsync(Encoding.ASCII.GetBytes(new string('A', 20_000)));
        });

        var engine = new ClamdEngine(new ClamdOptions { Port = server.Port });
        await Assert.ThrowsAsync<EngineUnavailableException>(() => engine.GetInfoAsync(Ct));
    }

    private static async Task<string> ReadCommand(NetworkStream s)
    {
        var sb = new StringBuilder();
        var b = new byte[1];
        while (await s.ReadAsync(b) == 1 && b[0] != 0)
        {
            sb.Append((char)b[0]);
        }

        return sb.ToString();
    }

    private sealed class FakeDaemon : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _loop;

        private FakeDaemon(Func<ScriptedStream, Task> script)
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            _loop = Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    TcpClient client;
                    try
                    {
                        client = await _listener.AcceptTcpClientAsync(_cts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }

                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            try
                            {
                                await script(new ScriptedStream(client.Client, _cts.Token));
                            }
                            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
                            {
                            }
                        }
                    });
                }
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public static FakeDaemon Start(Func<ScriptedStream, Task> script) => new(script);

        public static int FreePort()
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        public async ValueTask DisposeAsync()
        {
            await _cts.CancelAsync();
            _listener.Stop();
            await _loop;
            _cts.Dispose();
        }
    }

    private sealed class ScriptedStream(Socket socket, CancellationToken token) : NetworkStream(socket, ownsSocket: false)
    {
        public CancellationToken Token { get; } = token;
    }
}
