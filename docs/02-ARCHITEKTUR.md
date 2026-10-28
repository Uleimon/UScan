# 02 – Architektur

Legende: ✅ implementiert und getestet · 🟡 geplant, Schnittstelle festgelegt · ⛔ bewusst nicht vorgesehen

## 1. Prozesse und Sicherheitsgrenzen (Zielbild Windows)

```
 Benutzer-Sitzung (mittlere Integrität)          Dienste
┌───────────────────────────────┐       ┌──────────────────────────────────────┐
│ UScan.App (WPF)        🟡   │ Named │ UScan.Service           🟡         │
│  - zeigt nur Backend-Daten    │ Pipe  │  (LocalSystem, nur für privilegierte │
│  - keine Dateizugriffe für    │◄─────►│   Aktionen: Quarantäne, Inventar)    │
│    Scans                      │ ACL:  │  - ScanRunner          ✅            │
├───────────────────────────────┤ Nutzer│  - StatusEvaluator     ✅            │
│ uscan CLI              ✅   │ + Adm.│  - QuarantineStore     🟡            │
│  (Phase 1: spricht direkt     │       │  - Inventory/Behavior  🟡            │
│   mit clamd)                  │       │  - UpdateManager       🟡            │
└───────────────────────────────┘       └───────────┬──────────────────────────┘
                                                    │ TCP 127.0.0.1:3310, INSTREAM
                                                    ▼  (nur Dateiinhalt, keine Pfade)
                                        ┌──────────────────────────────────────┐
                                        │ clamd (ClamAV)          ✅ (Linux)   │
                                        │  eigenes virtuelles Dienstkonto,     │
                                        │  OHNE Lesezugriff auf Nutzerdateien  │
                                        └──────────────────────────────────────┘
                                        ┌──────────────────────────────────────┐
                                        │ Microsoft Defender (vorhanden)  🟡   │
                                        │  MpCmdRun / AMSI als 2. Meinung      │
                                        └──────────────────────────────────────┘
```

Wichtige Grenzen:

* **clamd erhält nur Bytes**, nie Pfade. Würde UScan die `SCAN <pfad>`-Befehle nutzen, könnte jeder lokale Prozess über den unauthentifizierten TCP-Port `clamd` dazu bringen, Dateien mit dessen Rechten zu öffnen. Deshalb: ausschließlich `INSTREAM`, `clamd` unter einem Konto ohne Dateirechte.
* **Die GUI ist unprivilegiert.** Destruktive Aktionen laufen im Dienst, nach Prüfung der Identität des Pipe-Clients und mit expliziter Bestätigung.
* **Netzwerk** nur für Signatur-/Programm-Updates und – nach ausdrücklicher Zustimmung – Hash-Reputation.

## 2. Module (Projektstruktur)

| Projekt | Inhalt | Status |
|---|---|---|
| `src/UScan.Core` | plattformneutrale Logik | ✅ |
| ├ `Model/` | `Verdict`, `FileScanResult`, `ScanReport`, `ScanProgress`, `EngineInfo` | ✅ |
| ├ `Engines/IScanEngine` | Engine-Abstraktion (Stream → Ergebnis) | ✅ |
| ├ `Engines/ClamAV/` | `ClamdEngine` (TCP, INSTREAM, VERSION, PING), `ClamdResponseParser` | ✅ |
| ├ `Hashing/` | `HashingReadStream` – SHA-256 im selben Lesedurchgang | ✅ |
| ├ `Scanning/` | `ScanRunner` (Aufzählung, Parallelität, Abbruch, Fehler), `ZipLimitInspector` | ✅ |
| └ `Status/` | `StatusEvaluator` – leitet den Dashboard-Status aus Fakten ab | ✅ |
| `src/UScan.Cli` | Kommandozeile `uscan status` / `uscan scan` | ✅ |
| `src/UScan.Windows` | Authenticode, Autostart/Dienste/Aufgaben-Inventar, Defender-Adapter, AMSI | 🟡 Phase 3 (nur mit Windows-Testumgebung) |
| `src/UScan.Service` | Windows-Dienst, IPC, Quarantäne, Zeitplan | 🟡 Phase 3 |
| `src/UScan.App` | WPF-Oberfläche | 🟡 Phase 4 |
| `tests/UScan.Core.Tests` | Unit- und Integrationstests (echter `clamd`) | ✅ |

## 3. Zentrale Schnittstellen

```csharp
public interface IScanEngine
{
    string Id { get; }
    long MaxStreamBytes { get; }                 // größere Dateien: Skipped/TooLarge, nie "Clean"
    Task<EngineInfo> GetInfoAsync(CancellationToken ct);
    Task<EngineResult> ScanAsync(Stream content, CancellationToken ct);
}
```

Geplante Erweiterungen (Phase 3), jeweils mit eigener Testsuite:

* `IReputationProvider` – nur SHA-256, nur bei Opt-in, Ergebnis `Known-Bad | Known-Good | Unknown` („Unbekannt“ ist nie „gefährlich“).
* `IHeuristicAnalyzer` – liefert gewichtete Merkmale mit Begründungstext; eine Warnung entsteht erst ab einer Schwelle aus mehreren unabhängigen Merkmalen.
* `IInventorySource` – Autostart (Run/RunOnce, Startup-Ordner), Dienste, geplante Aufgaben; jeweils mit Pfad, Hersteller, Authenticode-Status, Hash.
* `IQuarantineStore` – siehe Abschnitt 5.

## 4. Datenfluss eines Scans (implementiert)

1. `ScanRunner` fragt `GetInfoAsync`. Engine nicht erreichbar → Bericht `Aborted`, **keine** Datei wird als sauber gemeldet.
2. Ein Producer zählt Dateien auf (eigener Stack, Tiefenlimit, keine Reparse-Points/Symlinks, Zugriffsfehler je Verzeichnis als `ScanIssue`).
3. Consumer (konfigurierbare Parallelität) öffnen jede Datei **nur lesend** mit `FileShare.ReadWrite | Delete`, lesen sie **einmal**: die Bytes gehen gleichzeitig in SHA-256 und an `clamd`.
4. Das `clamd`-Ergebnis wird übersetzt: Signatur → `Infected`; andere `Heuristics.*` → `Suspicious`; Limit/Verschlüsselung → `Incomplete`; alles Unbekannte → `Error`.
5. Ein „sauberes“ ZIP wird zusätzlich gegen die Engine-Grenzen geprüft (siehe 01, Abschnitt 4).
6. Fortschritt wird ausschließlich aus erledigten Dateien berechnet; ein Prozentwert existiert erst, wenn die Aufzählung abgeschlossen ist.
7. Abbruch → `Cancelled`, nicht bearbeitete Dateien werden als Anzahl ausgewiesen, nicht als sauber.

## 5. Quarantäne (Entwurf für Phase 3)

* Ablage unter `%ProgramData%\UScan\Quarantine`, ACL: nur `SYSTEM` und Administratoren, Vererbung getrennt.
* Datei wird über ein **bereits geöffnetes Handle** gelesen (keine erneute Pfadauflösung → TOCTOU), mit zufälligem Schlüssel per AES-GCM verschlüsselt (verhindert versehentliches Ausführen und Fremdscanner-Alarme, bietet Integritätsprüfung), dann als `<GUID>.bin` + signierte Metadaten (`Originalpfad`, SHA-256, Erkennung, Engine-Version, Zeit) geschrieben; erst nach erfolgreichem `Flush` wird das Original gelöscht (Löschen über dasselbe Handle via `FILE_DISPOSITION_INFO`).
* **Schutzliste:** Dateien unter `%SystemRoot%`, signiert von Microsoft, oder in `WinSxS` werden nie automatisch verschoben; nur nach Bestätigung durch einen Administrator und mit Hinweis.
* **Wiederherstellung:** erneuter Scan des Inhalts, Prüfung des Zielpfads (kein Reparse-Point in der Kette, Zielordner existiert, Datei existiert nicht), Schreiben in temporäre Datei + atomares Umbenennen.
* Standardaktion bei Funden ist **„In Quarantäne verschieben“**, nie „Löschen“; endgültiges Löschen nur aus der Quarantäne mit Bestätigung.

## 6. Echtzeit- und Verhaltensmodul (Entwurf, ehrliche Abgrenzung)

| Fähigkeit | Technik | Was es **nicht** kann |
|---|---|---|
| Neue/geänderte Dateien nachscannen | `ReadDirectoryChangesW` bzw. USN-Journal (Admin) | Ausführung **nicht verhindern**; Prüfung erfolgt nach dem Schreiben |
| Massenänderungen erkennen (Ransomware-Indiz) | Änderungsrate + Entropieanstieg je Prozess/Ordner | Prozess nicht zuverlässig stoppen, bevor Dateien betroffen sind |
| Prozessketten | ETW-Provider `Microsoft-Windows-Kernel-Process` (Admin) | Kernel-Rootkits, die ETW manipulieren |
| Autostart-Änderungen | Registry-Benachrichtigung `RegNotifyChangeKeyValue`, Vergleich mit Baseline | Persistenz außerhalb der abgefragten Orte |

Echte Echtzeit-**Blockierung** übernimmt Defender. UScan empfiehlt (ohne selbst umzuschalten) „Überwachter Ordnerzugriff“ in Windows-Sicherheit als Ransomware-Schutz.

## 7. Updates (Entwurf)

* **Signaturen:** `freshclam` (prüft die digitale Signatur der CVD-Dateien von Cisco Talos). UScan überwacht Alter und Version und meldet „Update erforderlich“.
* **Programm:** Update-Manifest im Format von *The Update Framework* (TUF) oder gleichwertig: signierte Metadaten mit Versionsnummer (Downgrade-Schutz), Ablaufdatum (Freeze-Schutz), SHA-256 der Pakete. Root-Schlüssel offline/HSM, Signierschlüssel getrennt und rotierbar, keine Schlüssel im Quellcode. Installation in Seitenverzeichnis, Umschalten erst nach erfolgreichem Selbsttest, Rollback auf vorheriges Verzeichnis. Zusätzlich Authenticode-Signatur der Binärdateien.
