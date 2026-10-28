using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using UScan.Core.Engines;
using UScan.Core.Engines.ClamAV;
using UScan.Core.Model;
using UScan.Core.Scanning;
using UScan.Core.Status;

// Exit codes: 0 = scan completed, nothing found; 1 = detections; 2 = incomplete/errors/cancelled;
// 3 = engine unavailable; 64 = usage error.
var JsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
const int ExitClean = 0, ExitThreats = 1, ExitIncomplete = 2, ExitEngine = 3, ExitUsage = 64;

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    PrintUsage();
    return args.Length == 0 ? ExitUsage : ExitClean;
}

var command = args[0];
var paths = new List<string>();
string host = "127.0.0.1", jsonOut = "";
int port = 3310, parallel = 2;
long maxStreamMb = 100, maxFileMb = 100, maxScanMb = 400;
int maxFiles = 10_000;
var maxSignatureAgeDays = 3;

try
{
    for (var i = 1; i < args.Length; i++)
    {
        string Next() => ++i < args.Length ? args[i] : throw new ArgumentException($"Wert für {args[i - 1]} fehlt.");
        switch (args[i])
        {
            case "--host": host = Next(); break;
            case "--port": port = int.Parse(Next(), CultureInfo.InvariantCulture); break;
            case "--parallel": parallel = int.Parse(Next(), CultureInfo.InvariantCulture); break;
            case "--max-stream-mb": maxStreamMb = long.Parse(Next(), CultureInfo.InvariantCulture); break;
            case "--max-file-mb": maxFileMb = long.Parse(Next(), CultureInfo.InvariantCulture); break;
            case "--max-scan-mb": maxScanMb = long.Parse(Next(), CultureInfo.InvariantCulture); break;
            case "--max-files": maxFiles = int.Parse(Next(), CultureInfo.InvariantCulture); break;
            case "--max-signature-age-days": maxSignatureAgeDays = int.Parse(Next(), CultureInfo.InvariantCulture); break;
            case "--json": jsonOut = Next(); break;
            case var a when a.StartsWith("--", StringComparison.Ordinal): throw new ArgumentException($"Unbekannte Option {a}.");
            default: paths.Add(args[i]); break;
        }
    }
}
catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitUsage;
}

ClamdEngine engine;
try
{
    engine = new ClamdEngine(new ClamdOptions { Host = host, Port = port, MaxStreamBytes = maxStreamMb * 1024 * 1024 });
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    return ExitUsage;
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    Console.Error.WriteLine("Abbruch angefordert …");
    cts.Cancel();
};

switch (command)
{
    case "status":
        return await Status();
    case "scan" when paths.Count > 0:
        return await Scan();
    default:
        PrintUsage();
        return ExitUsage;
}

async Task<int> Status()
{
    var reachable = await engine.PingAsync(cts.Token);
    EngineInfo? info = null;
    if (reachable)
    {
        try
        {
            info = await engine.GetInfoAsync(cts.Token);
        }
        catch (EngineUnavailableException ex)
        {
            Console.Error.WriteLine(ex.Message);
        }
    }

    var assessment = new StatusEvaluator(TimeSpan.FromDays(maxSignatureAgeDays)).Evaluate(new StatusInputs(
        EngineReachable: reachable,
        Engine: info,
        ScanRunning: false,
        UnresolvedThreats: 0,
        PendingActions: 0,
        RealTimeMonitoringActive: null));

    Console.WriteLine($"Status:      {StateText(assessment.State)}");
    Console.WriteLine($"Engine:      {(reachable ? $"ClamAV {info?.EngineVersion ?? "?"} ({host}:{port})" : "nicht erreichbar")}");
    Console.WriteLine($"Signaturen:  {(info?.DatabaseVersion is { } v ? $"Version {v}, Stand {info.DatabaseTimestamp:yyyy-MM-dd HH:mm}" : "keine offizielle Datenbank erkannt")}");
    foreach (var r in assessment.Reasons)
    {
        Console.WriteLine($"  - {r}");
    }

    return reachable ? ExitClean : ExitEngine;
}

async Task<int> Scan()
{
    var runner = new ScanRunner(engine, new ScanOptions
    {
        MaxDegreeOfParallelism = parallel,
        ArchiveLimits = new ArchiveLimits(maxFileMb * 1024 * 1024, maxScanMb * 1024 * 1024, maxFiles, MaxCompressionRatio: 1000),
    });

    var lastPrint = DateTime.MinValue;
    var progress = new Progress<ScanProgress>(p =>
    {
        if (DateTime.UtcNow - lastPrint < TimeSpan.FromMilliseconds(500))
        {
            return;
        }

        lastPrint = DateTime.UtcNow;
        var pct = p.Fraction is { } f ? $"{f:P0}" : "Gesamtzahl noch unbekannt";
        Console.Error.Write($"\r{p.FilesCompleted}/{p.FilesDiscovered} Dateien ({pct}), {p.FilesSkipped} übersprungen, {p.Errors} Fehler   ");
    });

    var report = await runner.RunAsync(paths, progress, cts.Token);
    Console.Error.WriteLine();

    foreach (var f in report.Files.Where(f => f.Verdict != Verdict.Clean))
    {
        var reason = f.Verdict switch
        {
            Verdict.Skipped => $"übersprungen ({f.SkipReason})",
            _ => f.DetectionName ?? f.Message ?? "",
        };
        Console.WriteLine($"{VerdictText(f.Verdict),-14} {f.Path}  {reason}{(f.Sha256 is null ? "" : $"  sha256={f.Sha256}")}");
    }

    foreach (var issue in report.Issues)
    {
        Console.WriteLine($"{"HINWEIS",-14} {issue.Path}  {issue.Message}");
    }

    Console.WriteLine();
    Console.WriteLine($"Ergebnis:    {OutcomeText(report.Outcome)} nach {report.Duration.TotalSeconds:F1} s");
    Console.WriteLine($"Engine:      {(report.Engine is { } e ? $"ClamAV {e.EngineVersion}" : "nicht verfügbar")}");
    Console.WriteLine($"Dateien:     {report.FilesDiscovered} gefunden, {report.CountOf(Verdict.Clean)} ohne Befund, " +
                      $"{report.CountOf(Verdict.Infected)} infiziert, {report.CountOf(Verdict.Suspicious)} verdächtig, " +
                      $"{report.CountOf(Verdict.Incomplete)} unvollständig geprüft, {report.CountOf(Verdict.Skipped)} übersprungen, " +
                      $"{report.CountOf(Verdict.Error)} Fehler, {report.FilesNotProcessed} nicht bearbeitet");

    if (jsonOut.Length > 0)
    {
        await File.WriteAllTextAsync(jsonOut, JsonSerializer.Serialize(report, JsonOptions));
        Console.WriteLine($"Bericht:     {Path.GetFullPath(jsonOut)}");
    }

    if (report.Outcome == ScanOutcome.Aborted && report.Engine is null)
    {
        return ExitEngine;
    }

    if (report.ThreatsFound)
    {
        return ExitThreats;
    }

    var incomplete = report.Outcome != ScanOutcome.Completed
        || report.Files.Any(f => f.Verdict is Verdict.Error or Verdict.Incomplete or Verdict.Skipped)
        || report.Issues.Count > 0;
    return incomplete ? ExitIncomplete : ExitClean;
}

static string VerdictText(Verdict v) => v switch
{
    Verdict.Infected => "INFIZIERT",
    Verdict.Suspicious => "VERDÄCHTIG",
    Verdict.Incomplete => "UNVOLLSTÄNDIG",
    Verdict.Skipped => "ÜBERSPRUNGEN",
    Verdict.Error => "FEHLER",
    _ => "OK",
};

static string OutcomeText(ScanOutcome o) => o switch
{
    ScanOutcome.Completed => "abgeschlossen",
    ScanOutcome.Cancelled => "vom Benutzer abgebrochen",
    _ => "wegen Engine-Fehler abgebrochen",
};

static string StateText(ProtectionState s) => s switch
{
    ProtectionState.Protected => "Geschützt",
    ProtectionState.ScanRunning => "Scan läuft",
    ProtectionState.UpdateRequired => "Update erforderlich",
    ProtectionState.ProtectionLimited => "Schutz eingeschränkt",
    ProtectionState.ActionRequired => "Aktion erforderlich",
    ProtectionState.ThreatFound => "Bedrohung gefunden",
    _ => "Unbekannter Status",
};

static void PrintUsage() => Console.WriteLine("""
    UScan – On-Demand-Scanner (Phase 1, Kommandozeile)

    Verwendung:
      uscan status [--host 127.0.0.1] [--port 3310]
      uscan scan <Pfad> [<Pfad> …] [--json bericht.json] [--parallel 2]
                   [--max-stream-mb 100] [--max-file-mb 100] [--max-scan-mb 400] [--max-files 10000]

    Die Grenzwerte müssen zu StreamMaxLength, MaxFileSize, MaxScanSize und MaxFiles in clamd.conf passen.
    Exit-Codes: 0 nichts gefunden, 1 Funde, 2 unvollständig/Fehler/abgebrochen, 3 Engine nicht erreichbar, 64 Aufruf falsch.
    """);
