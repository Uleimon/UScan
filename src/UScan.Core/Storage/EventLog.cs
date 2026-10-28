using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UScan.Core.Storage;

public enum EventSeverity
{
    Info,
    Warning,
    Error,
    Threat,
}

/// <summary>One line in the event log. Kept flat so it stays readable and greppable.</summary>
public sealed record SecurityEvent(
    DateTimeOffset Time,
    EventSeverity Severity,
    string Category,
    string Message,
    string? Path = null,
    string? Detail = null);

/// <summary>
/// Append-only JSON Lines log with size-based rotation. Every write is flushed so that events
/// survive a crash. Corrupt lines (e.g. torn by a power loss) are skipped when reading.
/// </summary>
public sealed class JsonLinesEventLog
{
    internal static readonly JsonSerializerOptions Json = new()
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly string _directory;
    private readonly long _maxFileBytes;
    private readonly int _maxFiles;
    private readonly Lock _gate = new();

    public JsonLinesEventLog(string directory, long maxFileBytes = 5 * 1024 * 1024, int maxFiles = 5)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFileBytes, 1024);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFiles, 1);
        _directory = directory;
        _maxFileBytes = maxFileBytes;
        _maxFiles = maxFiles;
        Directory.CreateDirectory(directory);
    }

    public string CurrentFile => Path.Combine(_directory, "events.jsonl");

    public void Append(SecurityEvent e)
    {
        ArgumentNullException.ThrowIfNull(e);
        var line = JsonSerializer.Serialize(e, Json) + "\n";
        var bytes = Encoding.UTF8.GetBytes(line);
        lock (_gate)
        {
            var info = new FileInfo(CurrentFile);
            if (info.Exists && info.Length + bytes.Length > _maxFileBytes)
            {
                Rotate();
            }

            using var fs = new FileStream(CurrentFile, FileMode.Append, FileAccess.Write, FileShare.Read);
            fs.Write(bytes);
            fs.Flush(flushToDisk: true);
        }
    }

    /// <summary>Newest first, across rotated files, at most <paramref name="max"/> entries.</summary>
    public IReadOnlyList<SecurityEvent> ReadRecent(int max = 1000)
    {
        var result = new List<SecurityEvent>();
        lock (_gate)
        {
            foreach (var file in FilesNewestFirst())
            {
                string[] lines;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var reader = new StreamReader(fs, Encoding.UTF8);
                    lines = reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
                }
                catch (FileNotFoundException)
                {
                    continue;
                }

                for (var i = lines.Length - 1; i >= 0 && result.Count < max; i--)
                {
                    try
                    {
                        if (JsonSerializer.Deserialize<SecurityEvent>(lines[i], Json) is { } e)
                        {
                            result.Add(e);
                        }
                    }
                    catch (JsonException)
                    {
                        // torn or foreign line: skip, never fail the whole log
                    }
                }

                if (result.Count >= max)
                {
                    break;
                }
            }
        }

        return result;
    }

    private IEnumerable<string> FilesNewestFirst()
    {
        yield return CurrentFile;
        for (var i = 1; i < _maxFiles; i++)
        {
            yield return $"{CurrentFile}.{i}";
        }
    }

    private void Rotate()
    {
        var oldest = $"{CurrentFile}.{_maxFiles - 1}";
        if (_maxFiles == 1)
        {
            File.Delete(CurrentFile);
            return;
        }

        File.Delete(oldest);
        for (var i = _maxFiles - 2; i >= 1; i--)
        {
            var src = $"{CurrentFile}.{i}";
            if (File.Exists(src))
            {
                File.Move(src, $"{CurrentFile}.{i + 1}");
            }
        }

        File.Move(CurrentFile, $"{CurrentFile}.1");
    }
}
