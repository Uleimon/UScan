using System.Text;
using System.Text.Json;
using UScan.Core.Model;
using UScan.Core.Storage;

namespace UScan.Core.Scanning;

/// <summary>What was being scanned, so an interrupted scan can be continued with the same plan.</summary>
public sealed record ScanJournalHeader(DateTimeOffset StartedAt, ScanMode Mode, IReadOnlyList<string> Roots, int MaxDirectoryDepth, IReadOnlyList<string> Notes);

/// <summary>One finished file and its last-write time when it was scanned (to notice later changes).</summary>
public sealed record ScanJournalEntry(FileScanResult Result, long LastWriteTicks);

/// <summary>Summary of an interrupted scan for the user interface.</summary>
public sealed record InterruptedScan(ScanJournalHeader Header, int FilesDone, int Detections, DateTimeOffset LastActivity);

/// <summary>
/// Records every finished file of a running scan as one JSON line, flushed to the operating system
/// right away, so a scan that is interrupted (PC shut down, UScan closed, clamd gone) can continue
/// later instead of starting over. A file is only taken over when it is still unchanged (same size
/// and last-write time); errors are always scanned again.
/// </summary>
public sealed class ScanJournal : IDisposable
{
    private const string HeaderFile = "scan.json";
    private const string EntriesFile = "files.jsonl";

    private readonly string _directory;
    private readonly Dictionary<string, ScanJournalEntry> _done;
    private readonly Lock _gate = new();
    private StreamWriter? _writer;

    private ScanJournal(string directory, ScanJournalHeader header, Dictionary<string, ScanJournalEntry> done)
    {
        _directory = directory;
        Header = header;
        _done = done;
        var stream = new FileStream(Path.Combine(directory, EntriesFile), FileMode.Append, FileAccess.Write, FileShare.Read);
        _writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };
    }

    public ScanJournalHeader Header { get; }

    /// <summary>Number of files taken over from the interrupted run.</summary>
    public int PreviouslyDone { get; private init; }

    /// <summary>Starts a new journal, replacing any previous one in <paramref name="directory"/>.</summary>
    public static ScanJournal Start(string directory, ScanJournalHeader header)
    {
        ArgumentNullException.ThrowIfNull(header);
        Delete(directory);
        Directory.CreateDirectory(directory);
        AtomicFile.WriteAllBytes(Path.Combine(directory, HeaderFile), JsonSerializer.SerializeToUtf8Bytes(header, JsonLinesEventLog.Json));
        return new ScanJournal(directory, header, new Dictionary<string, ScanJournalEntry>(StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>Opens an interrupted journal to continue it, or returns null if there is none.</summary>
    public static ScanJournal? Resume(string directory)
    {
        if (ReadHeader(directory) is not { } header)
        {
            return null;
        }

        var done = ReadEntries(directory);
        return new ScanJournal(directory, header, done) { PreviouslyDone = done.Count };
    }

    /// <summary>Describes an interrupted scan without opening it for writing, or null if there is none.</summary>
    public static InterruptedScan? Peek(string directory)
    {
        if (ReadHeader(directory) is not { } header)
        {
            return null;
        }

        // Counted without parsing every line: a full scan journal can hold hundreds of thousands of
        // entries, and this runs when the scan page opens.
        var file = Path.Combine(directory, EntriesFile);
        int done = 0, detections = 0;
        if (File.Exists(file))
        {
            using var reader = new StreamReader(new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
            while (reader.ReadLine() is { } line)
            {
                if (!line.EndsWith('}'))
                {
                    continue; // cut off by a power loss
                }

                done++;
                if (line.Contains("\"Verdict\":\"Infected\"", StringComparison.Ordinal) || line.Contains("\"Verdict\":\"Suspicious\"", StringComparison.Ordinal))
                {
                    detections++;
                }
            }
        }

        var last = File.Exists(file) ? new DateTimeOffset(File.GetLastWriteTimeUtc(file)) : header.StartedAt;
        return new InterruptedScan(header, done, detections, last);
    }

    /// <summary>All results recorded so far (for a partial report).</summary>
    public IReadOnlyList<FileScanResult> Results()
    {
        lock (_gate)
        {
            return _done.Values.Select(e => e.Result).ToArray();
        }
    }

    /// <summary>The earlier result for this file if it is unchanged since then; errors are not reused.</summary>
    public FileScanResult? TryReuse(string path, DateTime lastWriteUtc)
    {
        ScanJournalEntry? entry;
        lock (_gate)
        {
            if (!_done.TryGetValue(path, out entry))
            {
                return null;
            }
        }

        if (entry.Result.Verdict == Verdict.Error || entry.LastWriteTicks != lastWriteUtc.Ticks)
        {
            return null;
        }

        try
        {
            return entry.Result.SizeBytes is { } size && new FileInfo(path).Length != size ? null : entry.Result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public void Append(FileScanResult result, DateTime lastWriteUtc)
    {
        ArgumentNullException.ThrowIfNull(result);
        var entry = new ScanJournalEntry(result, lastWriteUtc.Ticks);
        var line = JsonSerializer.Serialize(entry, JsonLinesEventLog.Json);
        lock (_gate)
        {
            _done[result.Path] = entry;
            _writer?.WriteLine(line);
        }
    }

    /// <summary>Closes and removes the journal (the scan finished and its report is saved).</summary>
    public void Complete()
    {
        Dispose();
        Delete(_directory);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _writer?.Dispose();
            _writer = null;
        }
    }

    public static void Delete(string directory)
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static ScanJournalHeader? ReadHeader(string directory)
    {
        var file = Path.Combine(directory, HeaderFile);
        try
        {
            return File.Exists(file) ? JsonSerializer.Deserialize<ScanJournalHeader>(File.ReadAllBytes(file), JsonLinesEventLog.Json) : null;
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return null;
        }
    }

    private static Dictionary<string, ScanJournalEntry> ReadEntries(string directory)
    {
        var done = new Dictionary<string, ScanJournalEntry>(StringComparer.OrdinalIgnoreCase);
        var file = Path.Combine(directory, EntriesFile);
        if (!File.Exists(file))
        {
            return done;
        }

        using var reader = new StreamReader(new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
        while (reader.ReadLine() is { } line)
        {
            try
            {
                // The last line can be cut off when the PC lost power while it was being written.
                if (JsonSerializer.Deserialize<ScanJournalEntry>(line, JsonLinesEventLog.Json) is { } entry)
                {
                    done[entry.Result.Path] = entry;
                }
            }
            catch (JsonException)
            {
            }
        }

        return done;
    }
}
