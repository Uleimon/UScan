using System.Text.Json;
using UScan.Core.Engines;
using UScan.Core.Engines.ClamAV;
using UScan.Core.Heuristics;
using UScan.Core.Inventory;
using UScan.Core.Model;
using UScan.Core.Monitoring;
using UScan.Core.Quarantine;
using UScan.Core.Scanning;
using UScan.Core.Status;
using UScan.Core.Storage;
using UScan.Core.Updates;

namespace UScan.Core.App;

public sealed record OpenDetection(string Path, string? Sha256, Verdict Verdict, string? DetectionName, DateTimeOffset FoundAt);

public sealed record AllowedFile(string Sha256, string Path, string Reason, DateTimeOffset AllowedAt);

/// <summary>Everything the dashboard shows, gathered from real component state in one place.</summary>
public sealed record StatusSnapshot(
    StatusAssessment Assessment,
    bool EngineReachable,
    EngineInfo? Engine,
    OnAccessProtection OnAccess,
    IReadOnlyList<string>? MonitoredFolders,
    IReadOnlyList<OpenDetection> OpenDetections,
    IReadOnlyList<QuarantineItem> QuarantineNeedingAction,
    int QuarantineCount,
    DateTimeOffset? LastScan,
    string? SettingsError);

/// <summary>
/// Composition root shared by the command line and the desktop UI, so both show identical facts.
/// </summary>
public sealed class UScanHost
{
    private readonly string? _settingsError;
    private readonly TimeProvider _time;

    public UScanHost(AppPaths paths, IPlatformServices platform, UScanSettings? settings = null, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(platform);
        Paths = paths;
        Platform = platform;
        _time = time ?? TimeProvider.System;
        Settings = settings ?? UScanSettings.Load(paths.Settings, out _settingsError);
        Directory.CreateDirectory(paths.Root);
        Log = new JsonLinesEventLog(paths.Logs);
        Reports = new ReportStore(paths.Reports);
        Quarantine = new QuarantineStore(paths.Quarantine, platform.ProtectionPolicy, Log, _time);
        Engine = new ClamdEngine(new ClamdOptions { Host = Settings.ClamdHost, Port = Settings.ClamdPort, MaxStreamBytes = Settings.MaxStreamMb * 1024 * 1024 });
    }

    public AppPaths Paths { get; }
    public IPlatformServices Platform { get; }
    public UScanSettings Settings { get; }
    public JsonLinesEventLog Log { get; }
    public ReportStore Reports { get; }
    public QuarantineStore Quarantine { get; }
    public ClamdEngine Engine { get; }

    public string HeartbeatFile => Path.Combine(Paths.Root, "monitor.heartbeat");
    public string AllowListFile => Path.Combine(Paths.Root, "allowed.json");
    public string AutostartBaselineFile => Path.Combine(Paths.Baselines, "autostart.json");

    public ArchiveLimits ArchiveLimits => new(
        Settings.ArchiveMaxFileMb * 1024 * 1024, Settings.ArchiveMaxScanMb * 1024 * 1024, Settings.ArchiveMaxFiles, MaxCompressionRatio: 1000);

    public ScanRunner CreateRunner(int? maxDepth = null, bool? heuristics = null, bool? secondOpinion = null, bool waitForEngine = false, ScanJournal? journal = null) =>
        new(Engine, new ScanOptions
        {
            WaitForEngineAtStart = waitForEngine,
            Journal = journal,
            MaxDegreeOfParallelism = Settings.EffectiveParallelism,
            MaxDirectoryDepth = maxDepth ?? 64,
            ArchiveLimits = ArchiveLimits,
            Heuristics = heuristics ?? Settings.HeuristicsEnabled ? [new PeAnalyzer(Platform.Signatures, _time), new ScriptAnalyzer()] : [],
            SecondOpinion = secondOpinion ?? Settings.DefenderSecondOpinion ? Platform.CreateSecondOpinion() : null,
        }, _time);

    public InventoryCollector CreateInventoryCollector() =>
        new(Platform.CreateInventorySources(new InventoryEntryFactory(new CommandLineResolver(), Platform.Signatures)), _time);

    public AutostartMonitor CreateAutostartMonitor() => new(CreateInventoryCollector(), AutostartBaselineFile, Log, _time);

    public ScanPlan Plan(ScanMode mode, IReadOnlyList<string>? customPaths = null)
    {
        var inventory = mode is ScanMode.Quick or ScanMode.Autostart && OperatingSystem.IsWindows() ? CreateInventoryCollector().Collect() : null;
        return new ScanPlanner().Create(mode, inventory, customPaths);
    }

    /// <summary>Where a running scan records its progress, so it can be continued after an interruption.</summary>
    public string InterruptedScanDirectory => Path.Combine(Paths.Root, "scan-in-progress");

    private string ReportSavedMarker => Path.Combine(InterruptedScanDirectory, "report-saved");

    /// <summary>A scan that was interrupted (PC shut down, UScan closed, cancelled, engine gone) and can be continued; null if none.</summary>
    public InterruptedScan? InterruptedScan() => ScanJournal.Peek(InterruptedScanDirectory);

    /// <summary>
    /// Runs a plan, stores the report and writes detections to the event log. With
    /// <paramref name="waitForEngine"/> (interactive scans) an engine that is not reachable yet is
    /// awaited for up to about 2 minutes instead of aborting at once. With <paramref name="resumable"/>
    /// every finished file is recorded, so an interrupted scan can be continued with
    /// <see cref="ResumeInterruptedAsync"/>; an older interrupted scan is closed first with a partial report.
    /// </summary>
    public async Task<(ScanReport Report, string ReportFile)> ScanAsync(ScanPlan plan, IProgress<ScanProgress>? progress, CancellationToken ct,
        bool? heuristics = null, bool? secondOpinion = null, bool waitForEngine = false, bool resumable = false)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ScanJournal? journal = null;
        if (resumable)
        {
            DiscardInterrupted();
            journal = ScanJournal.Start(InterruptedScanDirectory, new ScanJournalHeader(_time.GetUtcNow(), plan.Mode, plan.Roots, plan.MaxDirectoryDepth, plan.Notes));
        }

        Log.Append(new SecurityEvent(_time.GetUtcNow(), EventSeverity.Info, "scan", $"{plan.Mode} scan started ({plan.Roots.Count} root(s))."));
        return await RunAndRecordAsync(plan, journal, progress, heuristics, secondOpinion, waitForEngine, ct).ConfigureAwait(false);
    }

    /// <summary>Continues the interrupted scan: unchanged files already checked are taken over, the rest is scanned.</summary>
    public async Task<(ScanReport Report, string ReportFile)> ResumeInterruptedAsync(IProgress<ScanProgress>? progress, CancellationToken ct, bool waitForEngine = false)
    {
        var journal = ScanJournal.Resume(InterruptedScanDirectory) ?? throw new InvalidOperationException("There is no interrupted scan to continue.");
        File.Delete(ReportSavedMarker);
        var h = journal.Header;
        var plan = new ScanPlan(h.Mode, h.Roots, h.MaxDirectoryDepth, h.Notes);
        Log.Append(new SecurityEvent(_time.GetUtcNow(), EventSeverity.Info, "scan",
            $"{plan.Mode} scan resumed ({journal.PreviouslyDone} file(s) already checked since {h.StartedAt.ToLocalTime():g}; unchanged ones are not scanned again)."));
        return await RunAndRecordAsync(plan, journal, progress, null, null, waitForEngine, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Gives up the interrupted scan. If it ended without a report (e.g. the PC was switched off),
    /// a partial report with everything checked until then is saved first, so its detections are not lost.
    /// </summary>
    public string? DiscardInterrupted()
    {
        if (ScanJournal.Peek(InterruptedScanDirectory) is not { } interrupted)
        {
            return null;
        }

        string? file = null;
        if (!File.Exists(ReportSavedMarker) && ScanJournal.Resume(InterruptedScanDirectory) is { } journal)
        {
            using (journal)
            {
                var h = journal.Header;
                var files = journal.Results().OrderBy(r => r.Path, StringComparer.Ordinal).ToArray();
                var report = new ScanReport(Guid.NewGuid(), h.StartedAt, interrupted.LastActivity, ScanOutcome.Aborted, h.Roots, null, files.Length, files,
                    [new ScanIssue("(interrupted)", "The scan was interrupted (e.g. the PC was shut down) and not continued. Only the files listed here were checked.")]);
                file = Reports.Save(report);
                LogReport(h.Mode, report, file);
            }
        }

        ScanJournal.Delete(InterruptedScanDirectory);
        return file;
    }

    private async Task<(ScanReport Report, string ReportFile)> RunAndRecordAsync(ScanPlan plan, ScanJournal? journal, IProgress<ScanProgress>? progress,
        bool? heuristics, bool? secondOpinion, bool waitForEngine, CancellationToken ct)
    {
        ScanReport report;
        try
        {
            using var background = Settings.LowPriorityScan ? Platform.EnterBackgroundMode() : null;
            report = await CreateRunner(plan.MaxDirectoryDepth, heuristics, secondOpinion, waitForEngine, journal).RunAsync(plan.Roots, progress, ct).ConfigureAwait(false);
        }
        finally
        {
            journal?.Dispose();
        }

        var file = Reports.Save(report);
        if (journal is not null)
        {
            if (report.Outcome == ScanOutcome.Completed)
            {
                journal.Complete();
            }
            else
            {
                // Kept for "continue"; this run's report is already saved, so discarding needs no partial report.
                File.WriteAllText(ReportSavedMarker, file);
            }
        }

        LogReport(plan.Mode, report, file);
        return (report, file);
    }

    private void LogReport(ScanMode mode, ScanReport report, string file)
    {
        var allowed = AllowedHashes();
        var allowedHits = 0;
        foreach (var f in report.Files.Where(f => f.Verdict is Verdict.Infected or Verdict.Suspicious))
        {
            if (f.Sha256 is not null && allowed.Contains(f.Sha256))
            {
                // Still recorded in the report; only the user's own decision changes how it is logged.
                allowedHits++;
                Log.Append(new SecurityEvent(_time.GetUtcNow(), EventSeverity.Info, "scan",
                    $"{f.Verdict}: {f.DetectionName} (allowed by user as false positive, same SHA-256)", f.Path, f.Sha256));
                continue;
            }

            Log.Append(new SecurityEvent(_time.GetUtcNow(), f.Verdict == Verdict.Infected ? EventSeverity.Threat : EventSeverity.Warning,
                "scan", $"{f.Verdict}: {f.DetectionName}", f.Path, f.Sha256));
        }

        Log.Append(new SecurityEvent(_time.GetUtcNow(), report.Outcome == ScanOutcome.Completed ? EventSeverity.Info : EventSeverity.Warning, "scan",
            $"{mode} scan {report.Outcome}: {report.Files.Count} of {report.FilesDiscovered} files, {report.CountOf(Verdict.Infected)} infected, {report.CountOf(Verdict.Suspicious)} suspicious." +
            (allowedHits > 0 ? $" {allowedHits} of these allowed by user." : "") +
            (report.Outcome != ScanOutcome.Completed && report.Issues.FirstOrDefault(i => i.Path is "(engine)" or "(interrupted)") is { } reason ? $" Reason: {reason.Message}" : ""),
            null, file));
    }

    public FreshclamUpdater CreateSignatureUpdater() =>
        new(Settings.FreshclamPath ?? Platform.DefaultFreshclamPath, Settings.FreshclamConfig, null, Log, _time);

    public IReadOnlyList<AllowedFile> AllowList()
    {
        try
        {
            return File.Exists(AllowListFile)
                ? JsonSerializer.Deserialize<List<AllowedFile>>(File.ReadAllBytes(AllowListFile), JsonLinesEventLog.Json) ?? []
                : [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    /// <summary>SHA-256 values the user has allowed as false positives.</summary>
    public IReadOnlySet<string> AllowedHashes() => AllowList().Select(a => a.Sha256).ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Marks a detection as a false positive by its exact SHA-256. A changed file is not covered.</summary>
    public void Allow(string sha256, string path, string reason)
    {
        var list = AllowList().Where(a => !a.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase)).ToList();
        list.Add(new AllowedFile(sha256.ToLowerInvariant(), path, reason, _time.GetUtcNow()));
        AtomicFile.WriteAllBytes(AllowListFile, JsonSerializer.SerializeToUtf8Bytes(list, JsonLinesEventLog.Json));
        Log.Append(new SecurityEvent(_time.GetUtcNow(), EventSeverity.Warning, "allowlist", $"User marked detection as allowed: {reason}", path, sha256));
    }

    /// <summary>
    /// Allows an open detection as a false positive, but only if the file still has exactly the
    /// content that was scanned. Returns null on success, otherwise the reason it was refused.
    /// </summary>
    public string? AllowOpenDetection(string path, string reason)
    {
        var full = System.IO.Path.GetFullPath(path);
        var open = OpenDetections().FirstOrDefault(d => string.Equals(d.Path, full, StringComparison.OrdinalIgnoreCase));
        if (open?.Sha256 is null)
        {
            return "There is no open detection for this file.";
        }

        if (string.IsNullOrWhiteSpace(reason))
        {
            return "A reason is required (it is logged).";
        }

        string current;
        using (var s = File.OpenRead(full))
        {
            current = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(s));
        }

        if (!current.Equals(open.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            return "The file has changed since it was scanned. Scan it again first.";
        }

        Allow(current, full, reason);
        return null;
    }

    /// <summary>
    /// Detections from recent reports that are still present: the newest result for the path is a
    /// detection, the file still exists, and its hash is not on the allow list.
    /// </summary>
    public IReadOnlyList<OpenDetection> OpenDetections(int reportsToConsider = 30)
    {
        var allowed = AllowedHashes();
        var newest = new Dictionary<string, (FileScanResult Result, DateTimeOffset At)>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in Reports.List().Take(reportsToConsider))
        {
            if (Reports.Load(file) is not { } report)
            {
                continue;
            }

            foreach (var r in report.Files)
            {
                if (!newest.TryGetValue(r.Path, out var existing) || existing.At < report.StartedAt)
                {
                    newest[r.Path] = (r, report.StartedAt);
                }
            }
        }

        return newest.Values
            .Where(v => v.Result.Verdict is Verdict.Infected or Verdict.Suspicious)
            .Where(v => File.Exists(v.Result.Path) && (v.Result.Sha256 is null || !allowed.Contains(v.Result.Sha256)))
            .Select(v => new OpenDetection(v.Result.Path, v.Result.Sha256, v.Result.Verdict, v.Result.DetectionName, v.At))
            .OrderByDescending(d => d.FoundAt)
            .ToArray();
    }

    public async Task<StatusSnapshot> GetStatusAsync(bool scanRunning, CancellationToken ct)
    {
        var reachable = await Engine.PingAsync(ct).ConfigureAwait(false);
        EngineInfo? info = null;
        if (reachable)
        {
            try
            {
                info = await Engine.GetInfoAsync(ct).ConfigureAwait(false);
            }
            catch (EngineUnavailableException)
            {
            }
        }

        var onAccess = Platform.QueryOnAccessProtection();
        var monitored = MonitorHeartbeat.ReadActive(HeartbeatFile, _time);
        var open = OpenDetections();
        var quarantine = Quarantine.List();
        var needsAction = quarantine.Where(q => q.State == QuarantineState.OriginalNotRemoved && File.Exists(q.OriginalPath)).ToArray();
        var assessment = new StatusEvaluator(TimeSpan.FromDays(Settings.MaxSignatureAgeDays), _time).Evaluate(new StatusInputs(
            reachable, info, scanRunning, open.Count, needsAction.Length, onAccess.Active, monitored is not null));
        var reports = Reports.List();
        var last = reports.Count > 0 ? Reports.Load(reports[0])?.FinishedAt : null;
        return new StatusSnapshot(assessment, reachable, info, onAccess, monitored, open, needsAction, quarantine.Count, last, _settingsError);
    }
}
