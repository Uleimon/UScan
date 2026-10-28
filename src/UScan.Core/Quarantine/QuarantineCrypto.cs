using System.Buffers.Binary;
using System.Security.Cryptography;

namespace UScan.Core.Quarantine;

/// <summary>
/// Chunked AES-256-GCM container for quarantined files.
///
/// Purpose: (1) neutralise the content so it cannot be executed or opened by accident and does
/// not trigger other scanners, (2) detect any modification, truncation or chunk reordering.
/// It is NOT meant to hide the content from the local user: the per-item key is stored in the
/// item's metadata next to the payload.
///
/// Format: "USQ1" | repeat { u32 plaintextLength | ciphertext | 16-byte tag }.
/// AAD per chunk = itemId (16 bytes) | u64 chunkIndex | u8 isFinal.
/// </summary>
internal static class QuarantineCrypto
{
    public const int ChunkSize = 1024 * 1024;
    private const int TagSize = 16;
    private static ReadOnlySpan<byte> Magic => "USQ1"u8;

    public sealed record SealResult(string Sha256, long Length);

    public static async Task<SealResult> SealAsync(Stream plaintext, Stream output, Guid itemId, byte[] key, byte[] nonceBase, CancellationToken ct)
    {
        using var aes = new AesGcm(key, TagSize);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await output.WriteAsync(Magic.ToArray(), ct).ConfigureAwait(false);

        var current = new byte[ChunkSize];
        var next = new byte[ChunkSize];
        var currentLen = await plaintext.ReadAtLeastAsync(current, ChunkSize, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        long index = 0, total = 0;
        var cipher = new byte[ChunkSize];
        var tag = new byte[TagSize];
        var lenBuf = new byte[4];

        while (true)
        {
            // Look ahead one chunk so the last chunk can be flagged as final.
            var nextLen = currentLen == ChunkSize
                ? await plaintext.ReadAtLeastAsync(next, ChunkSize, throwOnEndOfStream: false, ct).ConfigureAwait(false)
                : 0;
            var isFinal = nextLen == 0;

            sha.AppendData(current, 0, currentLen);
            total += currentLen;
            aes.Encrypt(Nonce(nonceBase, index), current.AsSpan(0, currentLen), cipher.AsSpan(0, currentLen), tag, Aad(itemId, index, isFinal));

            BinaryPrimitives.WriteUInt32BigEndian(lenBuf, (uint)currentLen);
            await output.WriteAsync(lenBuf, ct).ConfigureAwait(false);
            await output.WriteAsync(cipher.AsMemory(0, currentLen), ct).ConfigureAwait(false);
            await output.WriteAsync(tag, ct).ConfigureAwait(false);

            if (isFinal)
            {
                break;
            }

            (current, next) = (next, current);
            currentLen = nextLen;
            index++;
        }

        CryptographicOperations.ZeroMemory(current);
        CryptographicOperations.ZeroMemory(next);
        return new SealResult(Convert.ToHexStringLower(sha.GetHashAndReset()), total);
    }

    /// <summary>Decrypts and verifies every chunk. Throws <see cref="QuarantineIntegrityException"/> on any tampering.</summary>
    public static async Task<SealResult> OpenAsync(Stream sealedInput, Stream output, Guid itemId, byte[] key, byte[] nonceBase, CancellationToken ct)
    {
        using var aes = new AesGcm(key, TagSize);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var magic = new byte[4];
        if (await sealedInput.ReadAtLeastAsync(magic, 4, throwOnEndOfStream: false, ct).ConfigureAwait(false) != 4 || !magic.AsSpan().SequenceEqual(Magic))
        {
            throw new QuarantineIntegrityException("Quarantine container header is missing or invalid.");
        }

        var lenBuf = new byte[4];
        var cipher = new byte[ChunkSize];
        var plain = new byte[ChunkSize];
        var tag = new byte[TagSize];
        long index = 0, total = 0;

        var have = await sealedInput.ReadAtLeastAsync(lenBuf, 4, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        if (have != 4)
        {
            throw new QuarantineIntegrityException("Quarantine container is truncated.");
        }

        while (true)
        {
            var len = BinaryPrimitives.ReadUInt32BigEndian(lenBuf);
            if (len > ChunkSize)
            {
                throw new QuarantineIntegrityException("Invalid chunk length.");
            }

            if (await sealedInput.ReadAtLeastAsync(cipher.AsMemory(0, (int)len), (int)len, throwOnEndOfStream: false, ct).ConfigureAwait(false) != len
                || await sealedInput.ReadAtLeastAsync(tag, TagSize, throwOnEndOfStream: false, ct).ConfigureAwait(false) != TagSize)
            {
                throw new QuarantineIntegrityException("Quarantine container is truncated.");
            }

            // Peek: is there another chunk?
            var nextHave = await sealedInput.ReadAtLeastAsync(lenBuf, 4, throwOnEndOfStream: false, ct).ConfigureAwait(false);
            if (nextHave is not (0 or 4))
            {
                throw new QuarantineIntegrityException("Trailing garbage after last chunk.");
            }

            var isFinal = nextHave == 0;
            try
            {
                aes.Decrypt(Nonce(nonceBase, index), cipher.AsSpan(0, (int)len), tag, plain.AsSpan(0, (int)len), Aad(itemId, index, isFinal));
            }
            catch (AuthenticationTagMismatchException ex)
            {
                throw new QuarantineIntegrityException($"Chunk {index} failed authentication (modified, reordered or truncated).", ex);
            }

            sha.AppendData(plain, 0, (int)len);
            total += len;
            await output.WriteAsync(plain.AsMemory(0, (int)len), ct).ConfigureAwait(false);
            if (isFinal)
            {
                break;
            }

            index++;
        }

        CryptographicOperations.ZeroMemory(plain);
        return new SealResult(Convert.ToHexStringLower(sha.GetHashAndReset()), total);
    }

    private static byte[] Nonce(byte[] nonceBase, long index)
    {
        var n = (byte[])nonceBase.Clone();
        var counter = BinaryPrimitives.ReadUInt64BigEndian(n.AsSpan(4)) ^ (ulong)index;
        BinaryPrimitives.WriteUInt64BigEndian(n.AsSpan(4), counter);
        return n;
    }

    private static byte[] Aad(Guid itemId, long index, bool isFinal)
    {
        var aad = new byte[16 + 8 + 1];
        itemId.TryWriteBytes(aad);
        BinaryPrimitives.WriteInt64BigEndian(aad.AsSpan(16), index);
        aad[24] = isFinal ? (byte)1 : (byte)0;
        return aad;
    }
}

public sealed class QuarantineIntegrityException : Exception
{
    public QuarantineIntegrityException(string message) : base(message) { }
    public QuarantineIntegrityException(string message, Exception inner) : base(message, inner) { }
    public QuarantineIntegrityException() { }
}
