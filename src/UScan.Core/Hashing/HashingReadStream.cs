using System.Security.Cryptography;

namespace UScan.Core.Hashing;

/// <summary>
/// Read-only pass-through stream that computes SHA-256 over every byte read, so a file
/// is read from disk exactly once for both hashing and scanning.
/// </summary>
public sealed class HashingReadStream : Stream
{
    private readonly Stream _inner;
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private byte[]? _final;

    public HashingReadStream(Stream inner)
    {
        ArgumentNullException.ThrowIfNull(inner);
        if (!inner.CanRead)
        {
            throw new ArgumentException("Stream must be readable.", nameof(inner));
        }

        _inner = inner;
    }

    public long BytesRead { get; private set; }

    public bool ReachedEnd { get; private set; }

    /// <summary>
    /// Reads any bytes the consumer did not read and returns the lowercase hex SHA-256 of the whole stream.
    /// </summary>
    public async Task<string> CompleteAsync(CancellationToken cancellationToken)
    {
        if (_final is null)
        {
            var buffer = new byte[81920];
            while (await ReadAsync(buffer, cancellationToken).ConfigureAwait(false) > 0)
            {
            }

            _final = _hash.GetHashAndReset();
        }

        return Convert.ToHexStringLower(_final);
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        var n = _inner.Read(buffer);
        Account(buffer[..n]);
        return n;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var n = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        Account(buffer.Span[..n]);
        return n;
    }

    private void Account(ReadOnlySpan<byte> data)
    {
        if (_final is not null)
        {
            throw new InvalidOperationException("Hash already finalised.");
        }

        if (data.IsEmpty)
        {
            ReachedEnd = true;
            return;
        }

        _hash.AppendData(data);
        BytesRead += data.Length;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => BytesRead; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _hash.Dispose();
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
