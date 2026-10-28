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

    public ScanRunner CreateRunner(int? maxDepth = null, bool? heuristics = null, bool? secondOpinion = null) =>
        new(Engine, new ScanOptions
        {
            MaxDegreeOfParallelism = Settings.Parallelism,
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

    /// <summary>Runs a plan, stores the report and writes detections to the event log.</summary>
    public async Task<(ScanReport Report, string ReportFile)> ScanAsync(ScanPlan plan, IProgress<ScanProgress>? progress, CancellationToken ct, bool? heuristics = null, bool? secondOpinion = null)
    {
        ArgumentNullException.ThrowIfNull(plan);
        Log.Append(new SecurityEvent(_time.GetUtcNow(), EventSeverity.Info, "scan", $"{plan.Mode} scan started ({plan.Roots.Count} root(s))."));
        var report = await CreateRunner(plan.MaxDirectoryDepth, heuristics, secondOpinion).RunAsync(plan.Roots, progress, ct).ConfigureAwait(false);
        var file = Reports.Save(report);
        foreach (var f in report.Files.Where(f => f.Verdict is Verdict.Infected or Verdict.Suspicious))
        {
            Log.Append(new SecurityEvent(_time.GetUtcNow(), f.Verdict == Verdict.Infected ? EventSeverity.Threat : EventSeverity.Warning,
                "scan", $"{f.Verdict}: {f.DetectionName}", f.Path, f.Sha256));
        }

        Log.Append(new SecurityEvent(_time.GetUtcNow(), report.Outcome == ScanOutcome.Completed ? EventSeverity.Info : EventSeverity.Warning, "scan",
            $"{plan.Mode} scan {report.Outcome}: {report.Files.Count} of {report.FilesDiscovered} files, {report.CountOf(Verdict.Infected)} infected, {report.CountOf(Verdict.Suspicious)} suspicious.", null, file));
        return (report, file);
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

    /// <summary>Marks a detection as a false positive by its exact SHA-256. A changed file is not covered.</summary>
    public void Allow(string sha256, string path, string reason)
    {
        var list = AllowList().Where(a => !a.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase)).ToList();
        list.Add(new AllowedFile(sha256.ToLowerInvariant(), path, reason, _time.GetUtcNow()));
        AtomicFile.WriteAllBytes(AllowListFile, JsonSerializer.SerializeToUtf8Bytes(list, JsonLinesEventLog.Json));
        Log.Append(new SecurityEvent(_time.GetUtcNow(), EventSeverity.Warning, "allowlist", $"User marked detection as allowed: {reason}", path, sha256));
    }

    /// <summary>
    /// Detections from recent reports that are still present: the newest result for the path is a
    /// detection, the file still exists, and its hash is not on the allow list.
    /// </summary>
    public IReadOnlyList<OpenDetection> OpenDetections(int reportsToConsider = 30)
    {
        var allowed = AllowList().Select(a => a.Sha256).ToHashSet(StringComparer.OrdinalIgnoreCase);
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
