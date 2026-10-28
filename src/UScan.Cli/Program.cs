using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using UScan.Core.App;
using UScan.Core.Model;
using UScan.Core.Monitoring;
using UScan.Core.Quarantine;
using UScan.Core.Scanning;
using UScan.Core.Status;
using UScan.Core.Storage;
using UScan.Core.Updates;

// Exit codes: 0 = ok / nothing found; 1 = detections or open threats; 2 = incomplete/errors/cancelled/refused;
// 3 = engine unavailable; 64 = usage error.
const int ExitOk = 0, ExitThreats = 1, ExitIncomplete = 2, ExitEngine = 3, ExitUsage = 64;
var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintUsage();
    return args.Length == 0 ? ExitUsage : ExitOk;
}

// ---- argument parsing ------------------------------------------------------------------------
var positional = new List<string>();
var flags = new HashSet<string>(StringComparer.Ordinal);
var values = new Dictionary<string, string>(StringComparer.Ordinal);
string[] valueOptions = ["--json", "--data", "--host", "--port", "--to", "--reason", "--count", "--manifest", "--signature", "--package", "--install-root", "--parallel"];
string[] flagOptions = ["--yes", "--quarantine", "--include-suspicious", "--admin-confirmed-protected", "--force", "--no-heuristics", "--no-second-opinion", "--changes"];
for (var i = 1; i < args.Length; i++)
{
    var a = args[i];
    if (valueOptions.Contains(a))
    {
        if (++i >= args.Length)
        {
            Console.Error.WriteLine($"Wert für {a} fehlt.");
            return ExitUsage;
        }

        values[a] = args[i];
    }
    else if (flagOptions.Contains(a))
    {
        flags.Add(a);
    }
    else if (a.StartsWith("--", StringComparison.Ordinal))
    {
        Console.Error.WriteLine($"Unbekannte Option {a}. Hilfe: uscan --help");
        return ExitUsage;
    }
    else
    {
        positional.Add(a);
    }
}

// ---- composition -----------------------------------------------------------------------------
var paths = values.TryGetValue("--data", out var dataDir) ? new AppPaths(dataDir) : AppPaths.Default;
var platform = CreatePlatform();

var settings = UScanSettings.Load(paths.Settings, out var settingsError);
if (settingsError is not null)
{
    Console.Error.WriteLine($"WARNUNG: {settingsError}");
}

try
{
    if (values.TryGetValue("--host", out var h))
    {
        settings = settings with { ClamdHost = h };
    }

    if (values.TryGetValue("--port", out var p))
    {
        settings = settings with { ClamdPort = int.Parse(p, CultureInfo.InvariantCulture) };
    }

    if (values.TryGetValue("--parallel", out var par))
    {
        settings = settings with { Parallelism = int.Parse(par, CultureInfo.InvariantCulture) };
    }

    if (settings.Validate() is { } invalid)
    {
        Console.Error.WriteLine(invalid);
        return ExitUsage;
    }
}
catch (Exception ex) when (ex is FormatException or OverflowException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitUsage;
}

UScanHost host;
try
{
    host = new UScanHost(paths, platform, settings);
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

try
{
    return (args[0], positional.FirstOrDefault()) switch
    {
        ("status", _) => await Status(),
        ("scan", _) when positional.Count > 0 => await Scan(),
        ("quarantine", "list") => QuarantineList(),
        ("quarantine", "add") when positional.Count == 2 => await QuarantineAdd(positional[1]),
        ("quarantine", "restore") when positional.Count == 2 => await QuarantineRestore(positional[1]),
        ("quarantine", "delete") when positional.Count == 2 => QuarantineDelete(positional[1]),
        ("quarantine", "verify") when positional.Count == 2 => await QuarantineVerify(positional[1]),
        ("allow", _) when positional.Count == 1 => Allow(positional[0]),
        ("inventory", _) => Inventory(),
        ("watch", _) => await Watch(),
        ("update", "signatures") => await UpdateSignatures(),
        ("update", "program") => UpdateProgram(),
        ("release", "keygen") when positional.Count == 2 => ReleaseKeygen(positional[1]),
        ("release", "sign") when positional.Count == 3 => ReleaseSign(positional[1], positional[2]),
        ("log", _) => ShowLog(),
        ("settings", _) => ShowSettings(),
        _ => Usage(),
    };
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Abgebrochen.");
    return ExitIncomplete;
}

// ---- commands --------------------------------------------------------------------------------
async Task<int> Status()
{
    var s = await host.GetStatusAsync(scanRunning: false, cts.Token);
    if (values.TryGetValue("--json", out var file))
    {
        await File.WriteAllTextAsync(file, JsonSerializer.Serialize(s, jsonOptions));
    }

    Console.WriteLine($"Status:            {StateText(s.Assessment.State)}");
    Console.WriteLine($"Scan-Engine:       {(s.EngineReachable ? $"ClamAV {s.Engine?.EngineVersion ?? "?"} ({settings.ClamdHost}:{settings.ClamdPort})" : "NICHT erreichbar")}");
    Console.WriteLine($"Signaturen:        {(s.Engine?.DatabaseVersion is { } v ? $"Version {v}, Stand {s.Engine.DatabaseTimestamp:yyyy-MM-dd HH:mm} UTC" : "keine offizielle Datenbank erkannt")}");
    Console.WriteLine($"Echtzeit-Schutz:   {(s.OnAccess.Active switch { true => "aktiv", false => "AUS", null => "unbekannt" })} – {s.OnAccess.Detail}");
    Console.WriteLine($"Dateiüberwachung:  {(s.MonitoredFolders is { } m ? $"läuft ({string.Join(", ", m)}) – Nachscan nach Änderung, kein Blockieren" : "läuft nicht")}");
    Console.WriteLine($"Offene Funde:      {s.OpenDetections.Count}");
    Console.WriteLine($"Quarantäne:        {s.QuarantineCount} Objekt(e){(s.QuarantineNeedingAction.Count > 0 ? $", {s.QuarantineNeedingAction.Count} Original(e) noch vorhanden" : "")}");
    Console.WriteLine($"Letzter Scan:      {(s.LastScan is { } l ? l.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) : "noch keiner")}");
    Console.WriteLine($"Plattform:         {platform.Name}");
    foreach (var r in s.Assessment.Reasons)
    {
        Console.WriteLine($"  - {r}");
    }

    foreach (var d in s.OpenDetections)
    {
        Console.WriteLine($"  ! {VerdictText(d.Verdict)} {d.Path} ({d.DetectionName})");
    }

    return !s.EngineReachable ? ExitEngine : s.OpenDetections.Count > 0 ? ExitThreats : ExitOk;
}

async Task<int> Scan()
{
    ScanPlan plan = positional[0] switch
    {
        "quick" when positional.Count == 1 => host.Plan(ScanMode.Quick),
        "full" when positional.Count == 1 => host.Plan(ScanMode.Full),
        "autostart" when positional.Count == 1 => host.Plan(ScanMode.Autostart),
        _ => host.Plan(ScanMode.Custom, positional),
    };

    foreach (var n in plan.Notes)
    {
        Console.Error.WriteLine($"Hinweis: {n}");
    }

    if (plan.Roots.Count == 0)
    {
        Console.Error.WriteLine("Nichts zu scannen.");
        return ExitIncomplete;
    }

    var lastPrint = DateTime.MinValue;
    var progress = new Progress<ScanProgress>(pr =>
    {
        if (DateTime.UtcNow - lastPrint < TimeSpan.FromMilliseconds(500))
        {
            return;
        }

        lastPrint = DateTime.UtcNow;
        var pct = pr.Fraction is { } f ? f.ToString("P0", CultureInfo.InvariantCulture) : "Gesamtzahl noch unbekannt";
        Console.Error.Write($"\r{pr.FilesCompleted}/{pr.FilesDiscovered} Dateien ({pct}), {pr.FilesSkipped} übersprungen, {pr.Errors} Fehler   ");
    });

    var (report, reportFile) = await host.ScanAsync(plan, progress, cts.Token,
        heuristics: flags.Contains("--no-heuristics") ? false : null,
        secondOpinion: flags.Contains("--no-second-opinion") ? false : null);
    Console.Error.WriteLine();

    foreach (var f in report.Files.Where(f => f.Verdict != Verdict.Clean))
    {
        var reason = f.Verdict == Verdict.Skipped ? $"übersprungen ({f.SkipReason})" : f.DetectionName ?? f.Message ?? "";
        Console.WriteLine($"{VerdictText(f.Verdict),-14} {f.Path}  {reason}");
        foreach (var e in f.EngineResults.Where(e => e.Verdict != Verdict.Clean && e.Detail is not null && e.EngineId != "clamav"))
        {
            Console.WriteLine($"{"",-14}   [{e.EngineId}] {e.Detail}");
        }
    }

    foreach (var issue in report.Issues)
    {
        Console.WriteLine($"{"HINWEIS",-14} {issue.Path}  {issue.Message}");
    }

    Console.WriteLine();
    Console.WriteLine($"Ergebnis:    {OutcomeText(report.Outcome)} nach {report.Duration.TotalSeconds:F1} s");
    Console.WriteLine($"Engine:      {(report.Engine is { } en ? $"ClamAV {en.EngineVersion}" : "nicht verfügbar")}");
    Console.WriteLine($"Dateien:     {report.FilesDiscovered} gefunden, {report.CountOf(Verdict.Clean)} ohne Befund, " +
                      $"{report.CountOf(Verdict.Infected)} infiziert, {report.CountOf(Verdict.Suspicious)} verdächtig, " +
                      $"{report.CountOf(Verdict.Incomplete)} unvollständig geprüft, {report.CountOf(Verdict.Skipped)} übersprungen, " +
                      $"{report.CountOf(Verdict.Error)} Fehler, {report.FilesNotProcessed} nicht bearbeitet");
    Console.WriteLine($"Bericht:     {reportFile}");
    if (values.TryGetValue("--json", out var jsonOut))
    {
        await File.WriteAllTextAsync(jsonOut, JsonSerializer.Serialize(report, jsonOptions));
        Console.WriteLine($"JSON-Kopie:  {Path.GetFullPath(jsonOut)}");
    }

    if (report.Outcome == ScanOutcome.Aborted && report.Engine is null)
    {
        return ExitEngine;
    }

    if (flags.Contains("--quarantine"))
    {
        var targets = report.Files.Where(f => f.Verdict == Verdict.Infected || (flags.Contains("--include-suspicious") && f.Verdict == Verdict.Suspicious)).ToArray();
        if (targets.Length > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"{targets.Length} Datei(en) werden in die Quarantäne verschoben (verschlüsselt, wiederherstellbar):");
            foreach (var t in targets)
            {
                Console.WriteLine($"  {t.Path}");
            }

            if (Confirm("In Quarantäne verschieben?"))
            {
                foreach (var t in targets)
                {
                    var r = await host.Quarantine.QuarantineAsync(t.Path, t.DetectionName ?? t.Verdict.ToString(), t.EngineResults.FirstOrDefault(e => e.Verdict == t.Verdict)?.EngineId ?? "?",
                        t.Sha256, flags.Contains("--admin-confirmed-protected"), cts.Token);
                    Console.WriteLine($"  {(r.Success ? "OK    " : "FEHLER")} {t.Path}: {r.Message}{(r.Item is { } it ? $" (ID {it.Id})" : "")}");
                }
            }
        }
    }

    if (report.ThreatsFound)
    {
        return ExitThreats;
    }

    var incomplete = report.Outcome != ScanOutcome.Completed
        || report.Files.Any(f => f.Verdict is Verdict.Error or Verdict.Incomplete or Verdict.Skipped)
        || report.Issues.Count > 0;
    return incomplete ? ExitIncomplete : ExitOk;
}

int QuarantineList()
{
    var items = host.Quarantine.List();
    if (items.Count == 0)
    {
        Console.WriteLine("Die Quarantäne ist leer.");
        return ExitOk;
    }

    foreach (var q in items)
    {
        Console.WriteLine($"{q.Id}  {q.QuarantinedAt.ToLocalTime():yyyy-MM-dd HH:mm}  {q.DetectionName} ({q.EngineId})");
        Console.WriteLine($"    {q.OriginalPath}  {q.SizeBytes} Bytes  sha256={q.Sha256}");
        if (q.State == QuarantineState.OriginalNotRemoved)
        {
            Console.WriteLine($"    ACHTUNG: Original ist noch vorhanden – {q.StateDetail}");
        }
    }

    return ExitOk;
}

async Task<int> QuarantineAdd(string file)
{
    // Always scan first: quarantining is tied to an actual detection and the scanned hash.
    var (report, _) = await host.ScanAsync(host.Plan(ScanMode.Custom, [file]), null, cts.Token);
    var r = report.Files.Count > 0 ? report.Files[0] : null;
    if (r is null || r.Verdict is not (Verdict.Infected or Verdict.Suspicious))
    {
        Console.WriteLine($"Kein Fund für {file} (Ergebnis: {(r is null ? "nicht gescannt" : VerdictText(r.Verdict))}). Es wird nichts verschoben.");
        return r is null ? ExitIncomplete : ExitOk;
    }

    Console.WriteLine($"{VerdictText(r.Verdict)}: {r.Path} ({r.DetectionName})");
    if (!Confirm("In Quarantäne verschieben?"))
    {
        return ExitIncomplete;
    }

    var q = await host.Quarantine.QuarantineAsync(r.Path, r.DetectionName ?? r.Verdict.ToString(), r.EngineResults.FirstOrDefault(e => e.Verdict == r.Verdict)?.EngineId ?? "?",
        r.Sha256, flags.Contains("--admin-confirmed-protected"), cts.Token);
    Console.WriteLine(q.Message + (q.Item is { } it ? $" (ID {it.Id})" : ""));
    return q.Success ? ExitOk : ExitIncomplete;
}

async Task<int> QuarantineRestore(string idText)
{
    if (!Guid.TryParse(idText, out var id) || host.Quarantine.Get(id) is not { } item)
    {
        Console.Error.WriteLine("Unbekannte Quarantäne-ID.");
        return ExitUsage;
    }

    Console.WriteLine($"Wiederherstellen: {item.OriginalPath} ({item.DetectionName})");
    Console.WriteLine("Die Datei wird vorher erneut gescannt. Ein Ziel, das schon existiert, wird nie überschrieben.");
    if (!Confirm("Wiederherstellen?"))
    {
        return ExitIncomplete;
    }

    var force = flags.Contains("--force");
    if (force && !Confirm("Die Datei wurde als Schadsoftware erkannt. Trotz Fund wiederherstellen (nur bei sicherem Fehlalarm)?"))
    {
        return ExitIncomplete;
    }

    var r = await host.Quarantine.RestoreAsync(id, host.Engine, values.GetValueOrDefault("--to"), force, cts.Token);
    Console.WriteLine(r.Message + (r.RescanVerdict is { } v ? $" (Nachscan: {VerdictText(v)})" : ""));
    return r.Success ? ExitOk : ExitIncomplete;
}

int QuarantineDelete(string idText)
{
    if (!Guid.TryParse(idText, out var id) || host.Quarantine.Get(id) is not { } item)
    {
        Console.Error.WriteLine("Unbekannte Quarantäne-ID.");
        return ExitUsage;
    }

    Console.WriteLine($"ENDGÜLTIG löschen: {item.OriginalPath} ({item.DetectionName}). Das kann nicht rückgängig gemacht werden.");
    if (!Confirm("Endgültig löschen?"))
    {
        return ExitIncomplete;
    }

    var ok = host.Quarantine.DeletePermanently(id, userConfirmed: true);
    Console.WriteLine(ok ? "Gelöscht." : "Löschen fehlgeschlagen.");
    return ok ? ExitOk : ExitIncomplete;
}

async Task<int> QuarantineVerify(string idText)
{
    if (!Guid.TryParse(idText, out var id))
    {
        return Usage();
    }

    var ok = await host.Quarantine.VerifyAsync(id, cts.Token);
    Console.WriteLine(ok ? "Quarantäne-Objekt ist unversehrt (Authentifizierung und SHA-256 stimmen)." : "Quarantäne-Objekt ist beschädigt oder fehlt.");
    return ok ? ExitOk : ExitIncomplete;
}

int Allow(string file)
{
    var full = Path.GetFullPath(file);
    var open = host.OpenDetections().FirstOrDefault(d => string.Equals(d.Path, full, StringComparison.OrdinalIgnoreCase));
    if (open?.Sha256 is null)
    {
        Console.Error.WriteLine("Für diese Datei gibt es keinen offenen Fund.");
        return ExitUsage;
    }

    string current;
    using (var s = File.OpenRead(full))
    {
        current = Convert.ToHexStringLower(SHA256.HashData(s));
    }

    if (!current.Equals(open.Sha256, StringComparison.OrdinalIgnoreCase))
    {
        Console.Error.WriteLine("Die Datei hat sich seit dem Scan verändert. Bitte erneut scannen.");
        return ExitIncomplete;
    }

    var reason = values.GetValueOrDefault("--reason") ?? "";
    if (reason.Length == 0)
    {
        Console.Error.WriteLine("Bitte mit --reason \"…\" begründen (wird protokolliert).");
        return ExitUsage;
    }

    Console.WriteLine($"Fund '{open.DetectionName}' für {full} als Fehlalarm zulassen. Gilt nur für genau diesen Dateiinhalt (SHA-256).");
    if (!Confirm("Zulassen?"))
    {
        return ExitIncomplete;
    }

    host.Allow(current, full, reason);
    Console.WriteLine("Zugelassen.");
    return ExitOk;
}

int Inventory()
{
    if (platform is GenericPlatformServices)
    {
        Console.Error.WriteLine("Das Autostart-Inventar ist nur unter Windows verfügbar.");
        return ExitIncomplete;
    }

    if (flags.Contains("--changes"))
    {
        var check = host.CreateAutostartMonitor().Check();
        if (check.BaselineCreated)
        {
            Console.WriteLine("Ausgangszustand gespeichert. Änderungen werden ab jetzt erkannt.");
        }

        foreach (var c in check.Changes)
        {
            Console.WriteLine($"{c.ChangeType,-9} {c.Entry.Kind,-26} {c.Entry.Name}  {c.Entry.Command}");
        }

        if (!check.BaselineCreated && check.Changes.Count == 0)
        {
            Console.WriteLine("Keine Änderungen seit der letzten Prüfung.");
        }

        PrintErrors(check.Errors);
        return check.Changes.Any(c => c.ChangeType != "Removed" && c.Entry.Signature?.IsTrusted != true) ? ExitThreats : ExitOk;
    }

    var snap = host.CreateInventoryCollector().Collect();
    foreach (var e in snap.Entries.OrderBy(e => e.Kind).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
    {
        var sig = e.Signature is { } s ? $"{s.Status}{(s.Signer is null ? "" : $" ({s.Signer})")}" : "-";
        Console.WriteLine($"{e.Kind,-26} {e.Name}");
        Console.WriteLine($"    {e.Command}");
        Console.WriteLine($"    Datei: {e.ImagePath ?? "?"}  vorhanden: {(e.FileExists is { } x ? (x ? "ja" : "NEIN") : "?")}  Signatur: {sig}");
        foreach (var o in e.Observations)
        {
            Console.WriteLine($"    Beobachtung: {o}");
        }
    }

    Console.WriteLine($"{snap.Entries.Count} Einträge. Beobachtungen sind Fakten, keine Schadsoftware-Urteile.");
    PrintErrors(snap.Errors);
    if (values.TryGetValue("--json", out var file))
    {
        File.WriteAllText(file, JsonSerializer.Serialize(snap, jsonOptions));
    }

    return snap.Errors.Count > 0 ? ExitIncomplete : ExitOk;
}

async Task<int> Watch()
{
    var roots = positional.Count > 0 ? positional.ToArray() : settings.WatchFolders.Count > 0 ? settings.WatchFolders.ToArray() : DefaultWatchFolders();
    roots = roots.Where(Directory.Exists).Select(Path.GetFullPath).ToArray();
    if (roots.Length == 0)
    {
        Console.Error.WriteLine("Keiner der Ordner existiert.");
        return ExitUsage;
    }

    if (!await host.Engine.PingAsync(cts.Token))
    {
        Console.Error.WriteLine("Scan-Engine (clamd) ist nicht erreichbar. Überwachung nicht gestartet.");
        return ExitEngine;
    }

    await using var watcher = new FileWatchService(roots, host.CreateRunner(), new WatchOptions { Exclusions = [paths.Root] }, host.Log);
    watcher.FileScanned += r =>
    {
        if (r.Verdict is Verdict.Infected or Verdict.Suspicious)
        {
            Console.WriteLine($"{DateTime.Now:HH:mm:ss} {VerdictText(r.Verdict)} {r.Path} ({r.DetectionName}) – Quarantäne: uscan quarantine add \"{r.Path}\"");
        }
    };
    watcher.Warning += w => Console.WriteLine($"{DateTime.Now:HH:mm:ss} WARNUNG {w}");
    watcher.Start();
    Console.WriteLine($"Überwache {string.Join(", ", roots)}");
    Console.WriteLine("Hinweis: Geänderte Dateien werden kurz danach gescannt. UScan blockiert keine Dateizugriffe; das übernimmt der Echtzeitschutz von Microsoft Defender.");
    Console.WriteLine("Beenden mit Strg+C.");

    var autostart = platform is GenericPlatformServices ? null : host.CreateAutostartMonitor();
    var nextAutostart = DateTime.UtcNow;
    try
    {
        while (!cts.IsCancellationRequested)
        {
            MonitorHeartbeat.Write(host.HeartbeatFile, roots);
            if (autostart is not null && DateTime.UtcNow >= nextAutostart)
            {
                nextAutostart = DateTime.UtcNow.AddMinutes(settings.AutostartCheckMinutes);
                foreach (var c in autostart.Check().Changes.Where(c => c.ChangeType != "Removed"))
                {
                    Console.WriteLine($"{DateTime.Now:HH:mm:ss} AUTOSTART {c.ChangeType}: {c.Entry.Kind} '{c.Entry.Name}' → {c.Entry.Command} (Signatur: {c.Entry.Signature?.Status.ToString() ?? "?"})");
                }
            }

            await Task.Delay(MonitorHeartbeat.Interval, cts.Token);
        }
    }
    catch (OperationCanceledException)
    {
    }
    finally
    {
        MonitorHeartbeat.Clear(host.HeartbeatFile);
    }

    var st = watcher.Status;
    Console.WriteLine($"Beendet. {st.FilesScanned} Dateien geprüft, {st.Detections} Funde, {st.LostEvents} verlorene Ereignisse.");
    return st.Detections > 0 ? ExitThreats : ExitOk;
}

async Task<int> UpdateSignatures()
{
    Console.WriteLine("Aktualisiere ClamAV-Signaturen mit freshclam (lädt von den offiziellen ClamAV-Mirrors, prüft deren digitale Signatur) …");
    var r = await host.CreateSignatureUpdater().UpdateAsync(cts.Token);
    Console.WriteLine(r.Summary);
    if (!r.Success && r.Output.Length > 0)
    {
        Console.WriteLine(r.Output.Trim());
    }

    if (r.Success)
    {
        Console.WriteLine("clamd lädt neue Signaturen selbst nach (SelfCheck in clamd.conf).");
    }

    return r.Success ? ExitOk : ExitIncomplete;
}

int UpdateProgram()
{
    if (!values.TryGetValue("--manifest", out var manifestPath) || !values.TryGetValue("--signature", out var sigPath) ||
        !values.TryGetValue("--package", out var packagePath) || !values.TryGetValue("--install-root", out var installRoot))
    {
        Console.Error.WriteLine("Benötigt --manifest, --signature, --package und --install-root.");
        return ExitUsage;
    }

    // Public release keys ship next to the program as keys/<keyId>.pem. No keys, no updates.
    var keyDir = Path.Combine(AppContext.BaseDirectory, "keys");
    var keys = Directory.Exists(keyDir)
        ? Directory.EnumerateFiles(keyDir, "*.pem").ToDictionary(f => Path.GetFileNameWithoutExtension(f), f => UpdateVerifier.LoadPublicKey(File.ReadAllText(f)))
        : [];
    if (keys.Count == 0)
    {
        Console.Error.WriteLine($"Programm-Updates sind nicht eingerichtet: kein öffentlicher Release-Schlüssel in {keyDir}.");
        return ExitIncomplete;
    }

    var installed = typeof(UScanHost).Assembly.GetName().Version ?? new Version(0, 0);
    var check = new UpdateVerifier(keys, installed).Verify(File.ReadAllBytes(manifestPath), File.ReadAllBytes(sigPath));
    Console.WriteLine(check.Reason);
    if (!check.Accepted)
    {
        return ExitIncomplete;
    }

    using var package = File.OpenRead(packagePath);
    if (!UpdateVerifier.VerifyPackage(package, check.Manifest!.Package, out var why))
    {
        Console.WriteLine(why);
        return ExitIncomplete;
    }

    package.Position = 0;
    var installer = new StagedInstaller(installRoot);
    var result = installer.Install(package, Version.Parse(check.Manifest.Version),
        dir => File.Exists(Path.Combine(dir, OperatingSystem.IsWindows() ? "uscan.exe" : "uscan.dll")));
    Console.WriteLine(result.Message);
    return result.Success ? ExitOk : ExitIncomplete;
}

int ReleaseKeygen(string dir)
{
    Directory.CreateDirectory(dir);
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var priv = Path.Combine(dir, "release-private.pem");
    var pub = Path.Combine(dir, "release-public.pem");
    if (File.Exists(priv))
    {
        Console.Error.WriteLine($"{priv} existiert bereits und wird nicht überschrieben.");
        return ExitUsage;
    }

    File.WriteAllText(priv, key.ExportPkcs8PrivateKeyPem());
    File.WriteAllText(pub, key.ExportSubjectPublicKeyInfoPem());
    Console.WriteLine($"Privater Schlüssel: {priv} – NICHT ins Repository, nicht mit dem Programm ausliefern.");
    Console.WriteLine($"Öffentlicher Schlüssel: {pub} – als keys/<keyId>.pem neben uscan ausliefern.");
    return ExitOk;
}

int ReleaseSign(string manifest, string privateKey)
{
    using var key = ECDsa.Create();
    key.ImportFromPem(File.ReadAllText(privateKey));
    var sig = key.SignData(File.ReadAllBytes(manifest), HashAlgorithmName.SHA256);
    File.WriteAllBytes(manifest + ".sig", sig);
    Console.WriteLine($"Signatur geschrieben: {manifest}.sig");
    return ExitOk;
}

int ShowLog()
{
    var count = values.TryGetValue("--count", out var c) && int.TryParse(c, CultureInfo.InvariantCulture, out var n) ? n : 50;
    foreach (var e in host.Log.ReadRecent(count))
    {
        Console.WriteLine($"{e.Time.ToLocalTime():yyyy-MM-dd HH:mm:ss} {e.Severity,-7} {e.Category,-10} {e.Message}{(e.Path is null ? "" : $"  [{e.Path}]")}");
    }

    return ExitOk;
}

int ShowSettings()
{
    Console.WriteLine($"Datenordner:   {paths.Root}");
    Console.WriteLine($"Einstellungen: {paths.Settings}{(File.Exists(paths.Settings) ? "" : " (nicht vorhanden, Standardwerte)")}");
    Console.WriteLine(JsonSerializer.Serialize(settings, jsonOptions));
    return ExitOk;
}

// ---- helpers ---------------------------------------------------------------------------------
bool Confirm(string question)
{
    if (flags.Contains("--yes"))
    {
        return true;
    }

    if (Console.IsInputRedirected)
    {
        Console.Error.WriteLine("Bestätigung erforderlich, aber keine Eingabe möglich. Mit --yes ausdrücklich bestätigen.");
        return false;
    }

    Console.Write($"{question} Zum Bestätigen \"ja\" eingeben: ");
    return string.Equals(Console.ReadLine()?.Trim(), "ja", StringComparison.OrdinalIgnoreCase);
}

static IPlatformServices CreatePlatform()
{
#if WINDOWS
    if (OperatingSystem.IsWindows())
    {
        return new UScan.Windows.WindowsPlatformServices();
    }
#endif
    return new GenericPlatformServices();
}

static string[] DefaultWatchFolders()
{
    var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    return [Path.Combine(profile, "Downloads"), Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)];
}

static void PrintErrors(IReadOnlyList<string> errors)
{
    foreach (var e in errors)
    {
        Console.WriteLine($"Nicht vollständig gelesen: {e}");
    }
}

int Usage()
{
    PrintUsage();
    return ExitUsage;
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
    UScan – Malware-Scanner für Windows (Kommandozeile)

      uscan status [--json datei]
      uscan scan quick | full | autostart
      uscan scan <Pfad> [<Pfad> …]
            [--quarantine [--include-suspicious]] [--no-heuristics] [--no-second-opinion] [--json datei]
      uscan quarantine list | add <Datei> | restore <ID> [--to <Pfad>] [--force] | delete <ID> | verify <ID>
      uscan allow <Datei> --reason "Begründung"        Fehlalarm zulassen (nur genau dieser Inhalt)
      uscan inventory [--changes] [--json datei]      Autostart, Dienste, geplante Aufgaben (Windows)
      uscan watch [<Ordner> …]                        Nachscan geänderter Dateien (blockiert nicht)
      uscan update signatures                         ClamAV-Signaturen über freshclam
      uscan update program --manifest m.json --signature m.json.sig --package p.zip --install-root <Ordner>
      uscan release keygen <Ordner> | release sign <manifest.json> <privat.pem>
      uscan log [--count 50]
      uscan settings

    Allgemein: --data <Ordner> (Datenordner), --host/--port (clamd), --parallel <n>, --yes (Rückfragen bestätigen)
    Exit-Codes: 0 ok, 1 Funde, 2 unvollständig/abgelehnt/abgebrochen, 3 Engine nicht erreichbar, 64 Aufruf falsch.
    """);
