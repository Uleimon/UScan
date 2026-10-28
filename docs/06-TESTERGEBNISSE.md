# 06 – Teststrategie und tatsächliche Testergebnisse

## Teststrategie

| Ebene | Werkzeug | Inhalt |
|---|---|---|
| Unit | xUnit v3 | Parser, Hashing, ZIP-Grenzen, Statuslogik, Scan-Orchestrierung (Fake-Engine), Quarantäne, Heuristik (synthetische PE-Dateien und Skripte), Inventar-Auflösung, Überwachung (simulierte Zeit), Updates (Signaturen, Downgrade, Zip-Slip), Speicher |
| Protokoll | xUnit + Fake-`clamd` (TCP) | INSTREAM-Framing, Verbindungsabbruch, Timeout, unerreichbarer Dienst, übergroße Antworten, Loopback-Erzwingung |
| Integration | xUnit + echter `clamd` | Fixture startet einen privaten `clamd` auf zufälligem Loopback-Port mit Test-Signatur (EICAR per MD5). Ohne ClamAV werden diese Tests als **übersprungen** gemeldet; die CI bricht dann ab. |
| End-to-End | echtes `uscan`-Programm + echter `clamd` | Scan → Fund → Status rot → Quarantäne nur mit Bestätigung → Status wieder ohne offenen Fund → Wiederherstellung abgelehnt (Nachscan findet weiterhin) → nur mit `--force` wiederhergestellt; Exit-Codes bei Engine-Ausfall und Fehlbedienung |
| Windows | xUnit auf `windows-latest` | WinVerifyTrust (eingebettet, Katalog, manipuliert, unsigniert), Registry/Startup/Dienste/Aufgaben, Defender-Zweitmeinung mit EICAR, Defender-Status, Fehlalarm-Messung, ViewModels der Oberfläche |
| Oberfläche | CI-Schritte auf `windows-latest` | Programm startet, Hauptfenster „UScan“ erscheint, Bildschirmfoto; Selbsttest (`UScan.exe --ui-selftest`) zeigt jede Seite und beide Farbschemata an und endet nur bei fehlerfreiem Layout/Binding mit Code 0 |

Testdaten: ausschließlich harmlos. EICAR wird zur Laufzeit zusammengesetzt; ZIP-Bomben bestehen aus Nullbytes; „verdächtige“ PE-Dateien werden im Test synthetisch erzeugt und nie ausgeführt. **Keine echte Malware.**

## Nachtrag Version 0.5.2

Die Abbruchmeldung nennt die Datei, bei der die Verbindung verloren ging. Wartezeit auf die Engine auf 24 × 5 s (2 min) verlängert, damit ein von Windows nach einem Absturz neu gestarteter `clamd`-Dienst (Wiederherstellungsoption, siehe docs/08) seine Signaturen laden kann. Tests: Linux 180/180.

## Nachtrag Version 0.5.1

Neu: Verbindungsverlust zu `clamd` bricht den Scan nicht mehr sofort ab. UScan prüft bis zu sechsmal im Abstand von 5 s, ob die Engine wieder antwortet, und scannt die betroffene Datei dann erneut; bricht `clamd` bei derselben Datei erneut ab, wird nur diese Datei als „Fehler“ gemeldet. Ist die Engine nach den Versuchen nicht erreichbar, wird der Scan wie bisher als abgebrochen gemeldet, jetzt mit dem Grund im Protokoll. Anlass: Ein vollständiger Scan auf einem echten Windows-PC brach nach 235 331 von 236 358 Dateien ab. Tests: Linux 180/180 (2 neue in ScanRunnerTests).

## Ergebnisse vom 28.10.2026 (Version 0.5.0)

### Linux (Entwicklungsumgebung und CI)

Ubuntu 24.04, .NET SDK 10.0, ClamAV 1.5.4 (Test-Signaturdatenbank mit einer Signatur).

```
dotnet test tests/UScan.Core.Tests  →  Passed: 178, Failed: 0, Skipped: 0
dotnet list package --vulnerable --include-transitive  →  keine bekannten Schwachstellen (alle 6 Projekte)
```

| Testdatei | Testmethoden |
|---|---|
| ClamdProtocolTests | 7 |
| ClamdResponseParserTests | 5 (mit vielen Datenzeilen) |
| HashingAndZipTests | 10 |
| HeuristicTests | 24 |
| InventoryTests | 12 |
| MonitoringTests | 11 |
| QuarantineTests | 14 |
| ScanPlannerTests | 3 |
| ScanRunnerTests | 13 |
| StatusEvaluatorTests | 9 |
| StorageTests | 7 |
| UpdateTests | 19 |
| ClamdIntegrationTests (echter clamd) | 10 |
| CliTests (echtes Programm + echter clamd) | 3 |

Theorien zählen je Datenzeile, daher 178 ausgeführte Tests.

### Windows (GitHub Actions, `windows-latest`, ClamAV 1.5.4 via Chocolatey, Microsoft Defender des Runners)

CI-Lauf 40679625206 (Commit „Fortschrittsbalken nur lesend gebunden …“):

```
UScan.Core.Tests     Passed: 178, Failed: 0, Skipped: 0
UScan.Windows.Tests  Passed:  17, Failed: 0, Skipped: 0
Oberfläche:          Fenstertitel 'UScan'
Selbsttest:          page ok: scan, quarantine, inventory, monitor, log, about, dashboard; theme switch ok
Build:               0 Warnungen, 0 Fehler (TreatWarningsAsErrors, Analyzer latest-recommended)
```

Die CI schlägt fehl, sobald auch nur ein Test übersprungen wird.

### Fehler, die erst durch Tests gefunden wurden (Auswahl)

| Befund | Gefunden durch | Behebung |
|---|---|---|
| Oberfläche stürzte beim Start ab (Stack Overflow, Code 0xC00000FD): `InvariantGlobalization` verhindert WPF-Textlayout, der Fehlerdialog löste das Layout erneut aus | CI-Starttest | Kulturdaten für die Oberfläche aktiviert, Fehlerdialog gegen Wiedereintritt gesichert |
| Beenden der Oberfläche hätte bei laufender Überwachung hängen können (Warten auf den UI-Thread aus dem UI-Thread) | CI-Selbsttest | Stoppen ohne UI-Thread-Abhängigkeit |
| Fortschrittsbalken: Zwei-Wege-Bindung an schreibgeschützte Eigenschaft (Absturz beim Öffnen der Scan-Seite) | CI-Selbsttest | Einweg-Bindung |
| Dateien in einem neu angelegten Unterordner wurden von der Überwachung nicht gesehen | Test mit echtem Dateisystem | Ordnerereignisse aktiviert, neue Ordner werden nachträglich durchsucht |
| Windows: TCP-Reset durch clamd verschluckt dessen Antwort → unbehandelte Ausnahme | Windows-CI | sauberer Engine-Fehler statt Absturz |
| ClamAV kürzt zu große ZIP-Einträge still und meldet „OK“ | Integrationstest | `ZipLimitInspector` → „Unvollständig“ |

### Fehlalarm-Messung (Heuristik, Windows-CI)

* PE-Heuristik gegen die ersten 500 `.exe`-Dateien in `C:\Windows\System32` des Runners (mindestens 100 gefordert), mit echter Authenticode-Prüfung: **0 als „verdächtig“ markiert**.
* Skript-Heuristik gegen alle `.vbs`, `.cmd`, `.bat`, `.js`, `.ps1` in `System32`: **0 markiert**.
* Grenzen der Aussage: nur von Microsoft signierte Systemdateien; gängige Fremdsoftware (Installer, Spiele, Entwicklerwerkzeuge) wurde nicht gemessen.

### Erkennung (nur mit Testdaten nachgewiesen)

* EICAR als Datei, im ZIP und mehrfach verschachtelt: erkannt (ClamAV).
* EICAR über Microsoft Defender (`MpCmdRun`) in der Windows-CI: erkannt, ohne dass Defender die Datei veränderte.
* Synthetische PE-Dateien mit W+X-Sektion, Packer-Namen, hoher Entropie und Injektions-Importen: „verdächtig“; dieselbe Datei mit gültiger Signatur: nicht markiert.
* Synthetische Skripte (Download-Cradle, Schattenkopien löschen, Dropper): „verdächtig“; harmlose Admin-Skripte: nicht markiert.
* **Nicht gemessen:** Erkennungsrate gegen reale Malware (bewusst keine echten Proben) und mit der offiziellen ClamAV-Datenbank.

### Leistung (eingeschränkt aussagekräftig)

Linux-Container, 4 vCPU, Release-Build, `uscan scan /usr/lib/python3.12 --parallel 4` (54 MB, 1 215 Dateien), Test-Signaturdatenbank, je 3 Läufe:

| Konfiguration | Dauer | Spitzen-RAM `uscan` |
|---|---|---|
| mit Heuristik | 1,75–1,89 s | 166–168 MB |
| ohne Heuristik | 1,78–2,02 s | 162–166 MB |

`clamd` mit Test-Datenbank ≈ 24 MB RSS. Mit der offiziellen Datenbank braucht `clamd` typischerweise über 1 GB RAM und scannt langsamer – diese Werte sind **nicht** auf einen echten Windows-PC übertragbar. Die Heuristik kostet hier kaum Zeit, weil der Ordner fast keine PE-Dateien oder Windows-Skripte enthält.

Überwachung: In den Tests wird eine neu abgelegte EICAR-Datei in einem neuen Unterordner nach ca. 0,3–0,6 s (Entprellung 300 ms im Test, Standard 2 s) gemeldet.

## Tests selbst ausführen

```bash
dotnet test                                   # alle Tests; Integration nur mit installiertem clamd
USCAN_CLAMD="C:\Program Files\ClamAV\clamd.exe" dotnet test    # Windows: Pfad explizit setzen
UScan.exe --ui-selftest                       # Oberfläche: alle Seiten einmal anzeigen, Code 0 = ok
```
