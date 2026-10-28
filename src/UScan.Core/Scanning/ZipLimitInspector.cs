using System.IO.Compression;

namespace UScan.Core.Scanning;

/// <summary>Limits that mirror the engine configuration (clamd.conf MaxFileSize / MaxScanSize / MaxFiles).</summary>
public sealed record ArchiveLimits(long MaxEntrySize, long MaxTotalSize, int MaxEntries, double MaxCompressionRatio)
{
    public static ArchiveLimits Default { get; } = new(
        MaxEntrySize: 100L * 1024 * 1024,
        MaxTotalSize: 400L * 1024 * 1024,
        MaxEntries: 10_000,
        MaxCompressionRatio: 1000);
}

/// <summary>
/// Reads only the ZIP central directory (no decompression) and reports why an engine's
/// "clean" answer may not cover the whole archive.
///
/// Background (verified with ClamAV 1.5.4, see docs/TEST_RESULTS.md): when a ZIP member is
/// larger than MaxFileSize, ClamAV scans only the first MaxFileSize bytes and still answers
/// "OK" without a Heuristics.Limits alert. This inspector closes that reporting gap.
/// Declared sizes come from the archive itself and can be forged; the engine's own limits
/// remain the enforcement mechanism, this is a reporting safeguard.
/// </summary>
internal static class ZipLimitInspector
{
    private static ReadOnlySpan<byte> LocalHeaderMagic => "PK\u0003\u0004"u8;

    public static bool LooksLikeZip(ReadOnlySpan<byte> header) => header.StartsWith(LocalHeaderMagic);

    /// <returns>null when the archive is within limits; otherwise a human-readable reason.</returns>
    public static string? FindCoverageGap(Stream seekableZip, ArchiveLimits limits)
    {
        try
        {
            using var zip = new ZipArchive(seekableZip, ZipArchiveMode.Read, leaveOpen: true);
            if (zip.Entries.Count > limits.MaxEntries)
            {
                return $"Archive has {zip.Entries.Count} entries; engine limit is {limits.MaxEntries}. Not all entries were scanned.";
            }

            long total = 0;
            foreach (var e in zip.Entries)
            {
                if (e.Length > limits.MaxEntrySize)
                {
                    return $"Entry '{e.FullName}' declares {e.Length} bytes; engine limit per entry is {limits.MaxEntrySize}. Only a part was scanned.";
                }

                if (e.CompressedLength > 0 && (double)e.Length / e.CompressedLength > limits.MaxCompressionRatio)
                {
                    return $"Entry '{e.FullName}' has compression ratio {(double)e.Length / e.CompressedLength:F0}:1 (limit {limits.MaxCompressionRatio:F0}:1), possible decompression bomb.";
                }

                total += e.Length;
                if (total > limits.MaxTotalSize)
                {
                    return $"Archive declares more than {limits.MaxTotalSize} bytes in total. Not all content was scanned.";
                }
            }

            return null;
        }
        catch (InvalidDataException ex)
        {
            return $"ZIP structure could not be read ({ex.Message}). Only the raw bytes were scanned, not the archive contents.";
        }
    }
}
