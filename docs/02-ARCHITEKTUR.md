# 02 – Architektur

Legende: ✅ implementiert und getestet · ⛔ bewusst nicht vorhanden · ⏭ für später vorgesehen (siehe Roadmap)

## 1. Prozesse und Sicherheitsgrenzen

```
 Benutzer-Sitzung (normale Rechte, kein Admin nötig)
┌──────────────────────────────┐   ┌──────────────────────────────┐
│ UScan.exe (WPF)          ✅ │   │ uscan (Kommandozeile)     ✅ │
│  ViewModels zeigen nur Daten │   │  status, scan, quarantine,   │
│  aus UScanHost               │   │  inventory, watch, update …  │
└──────────────┬───────────────┘   └──────────────┬───────────────┘
               └──────────────┬───────────────────┘
                              ▼
               ┌──────────────────────────────────────────────┐
               │ UScan.Core.App.UScanHost                 ✅  │  gemeinsame Zusammensetzung:
               │  ScanRunner · Heuristik · QuarantineStore    │  CLI und Oberfläche zeigen
               │  StatusEvaluator · Inventar · Überwachung    │  dieselben Fakten
               │  Berichte · Ereignisprotokoll · Updates      │
               └──────┬────────────────┬─────────────┬────────┘
     TCP 127.0.0.1    │ INSTREAM       │ Prozess     │ WMI / Win32 / COM (nur lesend)
     (nur Inhalt)     ▼                ▼             ▼
       ┌────────────────────┐ ┌──────────────────┐ ┌────────────────────────────────┐
       │ clamd (ClamAV)  ✅ │ │ MpCmdRun.exe  ✅ │ │ WinVerifyTrust, Registry, SCM,  │
       │ eigener Prozess    │ │ -DisableRemed.   │ │ Task Scheduler, MSFT_MpComputer-│
       └────────────────────┘ └──────────────────┘ │ Status, SecurityCenter2      ✅ │
                                                   └────────────────────────────────┘
```

Wichtige Grenzen:

* **clamd erhält nur Bytes**, nie Pfade. `SCAN <pfad>` würde jedem lokalen Prozess erlauben, Dateien mit den Rechten von clamd lesen zu lassen. Nicht-Loopback-Adressen werden abgelehnt.
* **Defender verändert nichts:** `-DisableRemediation` sorgt dafür, dass Defender nur berichtet. Ein Rückgabewert 2 ohne „Threat“-Zeile wird als Fehler gewertet, nicht als Fund.
* **Kein Dienst, kein Treiber.** UScan läuft vollständig mit den Rechten des angemeldeten Benutzers. Der ursprünglich geplante LocalSystem-Dienst mit Named-Pipe-IPC ist **nicht** umgesetzt (siehe [10](10-BEKANNTE-PROBLEME-UND-ROADMAP.md)). Folge: Dateien, die der Benutzer nicht lesen darf, werden als Fehler gemeldet; die Quarantäne liegt im Benutzerprofil.
* **Netzwerk** nutzt nur `freshclam` (Signaturen von den ClamAV-Mirrors). UScan selbst baut keine Internetverbindung auf.

## 2. Projekte

| Projekt | Inhalt | Status |
|---|---|---|
| `src/UScan.Core` (net10.0) | plattformneutrale Logik | ✅ |
| ├ `Engines/` | `IScanEngine` (Stream), `IFileScanEngine` (Datei, Zweitmeinung), `ClamdEngine` | ✅ |
| ├ `Scanning/` | `ScanRunner`, `ZipLimitInspector`, `ScanPlanner` (Schnell/Voll/Autostart/Benutzerdefiniert) | ✅ |
| ├ `Heuristics/` | `PeAnalyzer`, `ScriptAnalyzer` (inkl. Office-Makros), `HeuristicScorer` | ✅ |
| ├ `Quarantine/` | `QuarantineStore`, `QuarantineCrypto` (AES-256-GCM, Chunks), Schutzliste | ✅ |
| ├ `Inventory/` | Modelle, `CommandLineResolver`, `InventoryEntryFactory`, `InventoryDiff` | ✅ |
| ├ `Monitoring/` | `FileWatchService`, `ChangeDebouncer`, `MassChangeDetector`, `AutostartMonitor`, `MonitorHeartbeat` | ✅ |
| ├ `Updates/` | `FreshclamUpdater`, `UpdateVerifier`, `StagedInstaller` | ✅ |
| ├ `Status/` | `StatusEvaluator` (7 Zustände) | ✅ |
| ├ `Storage/` | `AppPaths`, `JsonLinesEventLog` (rotierend), `ReportStore`, `AtomicFile` | ✅ |
| └ `App/` | `UScanHost`, `UScanSettings`, `IPlatformServices` | ✅ |
| `src/UScan.Windows` (net10.0-windows) | `AuthenticodeVerifier`, Inventarquellen (Registry, Startup, Dienste, Aufgaben), `DefenderEngine`, `DefenderStatusProvider`, `WindowsPlatformServices` | ✅ |
| `src/UScan.Cli` (net10.0 + net10.0-windows) | Kommandozeile `uscan` | ✅ |
| `src/UScan.Desktop` (WPF) | Oberfläche `UScan.exe` | ✅ |
| `tests/UScan.Core.Tests` | Unit-, Protokoll-, Integrations- (echter clamd) und End-to-End-Tests der CLI | ✅ |
| `tests/UScan.Windows.Tests` | Tests gegen echte Windows-APIs, Defender, Fehlalarm-Messung, ViewModels | ✅ (nur Windows) |

## 3. Zentrale Schnittstellen

```csharp
public interface IScanEngine            // ClamAV
{
    string Id { get; }
    long MaxStreamBytes { get; }          // größere Dateien: Skipped/TooLarge, nie "Clean"
    Task<EngineInfo> GetInfoAsync(CancellationToken ct);
    Task<EngineResult> ScanAsync(Stream content, CancellationToken ct);
}

public interface IFileScanEngine        // Defender als Zweitmeinung
{
    string Id { get; }
    Task<EngineResult> ScanFileAsync(string path, CancellationToken ct);
}

public interface IHeuristicAnalyzer
{
    bool CanAnalyze(string path, ReadOnlySpan<byte> header);
    HeuristicResult Analyze(string path, Stream content);   // gewichtete Merkmale + Begründung
}

public interface IInventorySource { string Name { get; } IEnumerable<InventoryEntry> Collect(ICollection<string> errors); }

public interface IPlatformServices      // Windows: WindowsPlatformServices, sonst GenericPlatformServices
{
    ISignatureVerifier Signatures { get; }
    IFileProtectionPolicy ProtectionPolicy { get; }
    IReadOnlyList<IInventorySource> CreateInventorySources(InventoryEntryFactory f);
    IFileScanEngine? CreateSecondOpinion();
    OnAccessProtection QueryOnAccessProtection();   // Active: true/false/null (= unbekannt)
}
```

## 4. Ablauf eines Scans

1. `ScanPlanner` erzeugt den Plan (Wurzeln, Tiefenlimit, Hinweise, was **nicht** abgedeckt ist).
2. `ScanRunner` fragt die Engine-Version ab. Nicht erreichbar → Bericht `Aborted`, keine Datei wird als sauber gemeldet.
3. Aufzählung ohne Reparse-Points, mit Tiefenlimit; Zugriffsfehler je Verzeichnis werden als Hinweis erfasst.
4. Jede Datei wird einmal gelesen: Bytes gehen gleichzeitig in SHA-256 und an clamd.
5. Ergebnis „sauber“ bei Archiven → `ZipLimitInspector` prüft, ob ClamAV wegen Grenzen still gekürzt hat → ggf. „Unvollständig“.
6. Ergebnis „sauber“ und Datei ≤ 64 MB → Heuristiken; Punktzahl ≥ 60 aus mindestens zwei Merkmalen → „Verdächtig“ mit Begründung.
7. „Infiziert“/„Verdächtig“ → Defender prüft dieselbe Datei. Defender kann „Verdächtig“ zu „Infiziert“ hochstufen, aber nie einen Fund aufheben.
8. Bericht wird atomar gespeichert, Funde landen im Ereignisprotokoll.

## 5. Quarantäne (umgesetzt)

* Ablage: `%LOCALAPPDATA%\UScan\quarantine` (pro Benutzer).
* Verschlüsselung: AES-256-GCM in 64-KB-Blöcken, zufälliger Schlüssel und Nonce je Objekt, Blockindex und „letzter Block“ in den Zusatzdaten (verhindert Abschneiden und Vertauschen). Zweck ist **Unschädlichmachen und Integrität**, nicht Geheimhaltung: der Schlüssel liegt in den Metadaten daneben.
* Ablauf: Kopie verschlüsseln → zurücklesen und prüfen → Original im eigenen Ordner umbenennen → erneut hashen → nur bei Gleichheit löschen. Weicht etwas ab, bleibt das Original erhalten und der Zustand heißt `OriginalNotRemoved`.
* Schutzliste: Windows, Programme, ProgramData\Microsoft, Recovery, Boot – nur mit ausdrücklicher Admin-Bestätigung.
* Wiederherstellung: authentifiziert entschlüsseln, erneut scannen (Fund → Ablehnung, außer der Nutzer bestätigt einen Fehlalarm), kein Reparse-Point im Zielpfad, kein Überschreiben, Temp-Datei + Umbenennen.

## 6. Überwachung (umgesetzt, mit Grenzen)

| Fähigkeit | Technik | Grenze |
|---|---|---|
| Nachscan geänderter Dateien | `FileSystemWatcher` (ReadDirectoryChangesW), Entprellung 2 s, Wiederholung bei gesperrten Dateien | **blockiert nicht**; Pufferüberlauf → Warnung „manuell scannen“ |
| Massenänderungen | verschiedene Dateien je 60 s, Schwelle 300 | nur Hinweis, kein Stoppen von Prozessen, kein Prozessbezug |
| Autostart-Änderungen | Inventar-Vergleich mit gespeicherter Baseline (Standard alle 15 min) | Polling, Änderungen werden nicht rückgängig gemacht |
| Laufzeitstatus | Heartbeat-Datei, die andere Prozesse (Status, Oberfläche) lesen | nur, solange `uscan watch` oder die Oberfläche läuft |

## 7. Updates (umgesetzt)

* **Signaturen:** `freshclam` lädt von den offiziellen Mirrors und prüft die digitale Signatur jeder Datenbank. UScan wertet die dokumentierten Rückgabecodes aus (z. B. 52 Netzwerk, 54 Signaturprüfung fehlgeschlagen).
* **Programm:** Manifest (JSON) mit Produkt, Kanal, Version, Veröffentlichungs- und Ablaufdatum, Schlüssel-ID und SHA-256/Größe des Pakets; abgesetzte ECDSA-P-256-Signatur. Prüfung: Signatur → Produkt/Kanal → Version > installiert → nicht abgelaufen → Paket-Hash/-Größe. Installation in `versions/<v>`, Umschalten erst nach Selbsttest, `previous.txt` für Rollback; Entpacken mit Schutz gegen Pfad-Traversal, Links und Größenbomben.
* Ein Download-Client ist bewusst **nicht** eingebaut (siehe Roadmap); Updates werden heute als Dateien übergeben.
