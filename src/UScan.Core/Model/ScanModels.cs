namespace UScan.Core.Model;

/// <summary>
/// Final classification of one scanned object. The values are deliberately
/// fine-grained so that "not checked" is never displayed as "clean".
/// </summary>
public enum Verdict
{
    /// <summary>The engine scanned the complete content and reported no detection.</summary>
    Clean,

    /// <summary>A signature from a trusted database matched.</summary>
    Infected,

    /// <summary>A heuristic matched. Needs human review, never auto-deleted.</summary>
    Suspicious,

    /// <summary>The engine stopped early (size, recursion or time limit, encrypted archive). Content was NOT fully checked.</summary>
    Incomplete,

    /// <summary>The object was intentionally not scanned (see <see cref="SkipReason"/>).</summary>
    Skipped,

    /// <summary>Reading or scanning failed.</summary>
    Error,
}

public enum SkipReason
{
    None,
    ReparsePointOrSymlink,
    TooLarge,
    NotARegularFile,
}

/// <summary>Result returned by a single engine for a single stream.</summary>
/// <param name="Verdict">Engine classification.</param>
/// <param name="EngineId">Stable engine identifier, e.g. "clamav".</param>
/// <param name="DetectionName">Signature or heuristic name, if any.</param>
/// <param name="Detail">Raw engine message for the log (never shown as a detection reason on its own).</param>
public sealed record EngineResult(Verdict Verdict, string EngineId, string? DetectionName, string? Detail);

/// <summary>Version information reported by an engine.</summary>
/// <param name="EngineId">Stable engine identifier.</param>
/// <param name="EngineVersion">Program version, e.g. "1.5.4".</param>
/// <param name="DatabaseVersion">Signature database version, if the engine reports one.</param>
/// <param name="DatabaseTimestamp">Signature build time, if reported. Used to decide "update required".</param>
public sealed record EngineInfo(string EngineId, string EngineVersion, long? DatabaseVersion, DateTimeOffset? DatabaseTimestamp);

public sealed record FileScanResult(
    string Path,
    long? SizeBytes,
    string? Sha256,
    Verdict Verdict,
    SkipReason SkipReason,
    IReadOnlyList<EngineResult> EngineResults,
    string? Message,
    TimeSpan Duration)
{
    /// <summary>The detection name of the first engine that produced a non-clean verdict.</summary>
    public string? DetectionName => EngineResults.FirstOrDefault(r => r.DetectionName is not null)?.DetectionName;
}

/// <summary>
/// Progress derived exclusively from completed work. <see cref="Fraction"/> is null until
/// enumeration is finished, because before that the total is unknown.
/// </summary>
public sealed record ScanProgress(
    long FilesDiscovered,
    long FilesCompleted,
    long FilesSkipped,
    long Errors,
    long BytesScanned,
    bool EnumerationComplete,
    string? CurrentPath)
{
    public double? Fraction => EnumerationComplete && FilesDiscovered > 0
        ? (double)FilesCompleted / FilesDiscovered
        : null;
}

public enum ScanOutcome
{
    /// <summary>Every discovered file has a result. Says nothing about whether threats were found.</summary>
    Completed,
    Cancelled,
    /// <summary>The engine failed so the scan could not continue.</summary>
    Aborted,
}

public sealed record ScanReport(
    Guid ScanId,
    DateTimeOffset StartedAt,
    DateTimeOffset FinishedAt,
    ScanOutcome Outcome,
    IReadOnlyList<string> Roots,
    EngineInfo? Engine,
    long FilesDiscovered,
    IReadOnlyList<FileScanResult> Files,
    IReadOnlyList<ScanIssue> Issues)
{
    public TimeSpan Duration => FinishedAt - StartedAt;
    public int CountOf(Verdict v) => Files.Count(f => f.Verdict == v);
    public bool ThreatsFound => Files.Any(f => f.Verdict is Verdict.Infected or Verdict.Suspicious);

    /// <summary>Discovered files that have no result because the scan was cancelled or aborted.</summary>
    public long FilesNotProcessed => FilesDiscovered - Files.Count;
}

/// <summary>A problem that is not tied to a scanned file, e.g. an inaccessible directory.</summary>
public sealed record ScanIssue(string Path, string Message);
