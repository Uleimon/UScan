using System.Globalization;
using System.Text.Json;
using UScan.Core.Model;

namespace UScan.Core.Storage;

/// <summary>Stores complete scan reports as JSON, written atomically (temp file + rename).</summary>
public sealed class ReportStore
{
    private readonly string _directory;
    private readonly int _keep;

    public ReportStore(string directory, int keep = 100)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentOutOfRangeException.ThrowIfLessThan(keep, 1);
        _directory = directory;
        _keep = keep;
        Directory.CreateDirectory(directory);
    }

    public string Save(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var name = string.Create(CultureInfo.InvariantCulture, $"{report.StartedAt:yyyyMMdd'T'HHmmss}_{report.ScanId:N}.json");
        var path = Path.Combine(_directory, name);
        AtomicFile.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(report, JsonLinesEventLog.Json));
        Prune();
        return path;
    }

    public IReadOnlyList<string> List() =>
        Directory.EnumerateFiles(_directory, "*.json").OrderDescending(StringComparer.Ordinal).ToArray();

    public ScanReport? Load(string path)
    {
        try
        {
            return JsonSerializer.Deserialize<ScanReport>(File.ReadAllBytes(path), JsonLinesEventLog.Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private void Prune()
    {
        foreach (var old in List().Skip(_keep))
        {
            File.Delete(old);
        }
    }
}

public static class AtomicFile
{
    /// <summary>Writes to a sibling temp file, flushes to disk, then replaces the target in one rename.</summary>
    public static void WriteAllBytes(string path, ReadOnlySpan<byte> data)
    {
        var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(data);
                fs.Flush(flushToDisk: true);
            }

            File.Move(tmp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(tmp))
            {
                File.Delete(tmp);
            }
        }
    }
}
