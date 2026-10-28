# 01 – Analyse: Umgebung, Supportstatus, Technologiewahl

Stand: 28.10.2026. Alle Datumsangaben unten sind mit Quelle versehen und vor einem Release erneut zu prüfen.

## 1. Entwicklungsumgebung dieser Phase (ehrlich dokumentiert)

| Punkt | Befund |
|---|---|
| System | Linux-Cloud-Container (Ubuntu 24.04, 4 Kerne, 15 GB RAM), **kein Windows** |
| Installiert | .NET SDK 10.0.113, ClamAV 1.5.4 (`clamd`, `clamscan`) aus den Ubuntu-Paketquellen |
| Netzwerk | NuGet erreichbar. **Offizielle ClamAV-Signaturen nicht ladbar** (`freshclam` gegen `database.clamav.net` scheitert mit Verbindungsabbruch) |
| Folgen | Windows-spezifischer Code (Dienst, Registry, Authenticode, WMI, ETW, GUI) kann hier **weder ausgeführt noch getestet** werden. Er wird erst geschrieben, wenn er auf Windows getestet werden kann (CI mit `windows-latest`-Runner oder lokal). Erkennungstests nutzen eine **eigene Test-Signatur** (EICAR per MD5), nicht die offizielle Datenbank. |

Der Kern ist deshalb plattformneutral geschrieben (.NET 10, TCP zu `clamd`) und läuft unter Windows identisch; die Windows-Version von ClamAV unterstützt dasselbe `clamd`-Protokoll über TCP.

## 2. Supportstatus der Zielplattformen

| Produkt | Status am 28.10.2026 | Quelle |
|---|---|---|
| Windows 10 22H2 (Home/Pro) | Regulärer Support endete am 14.10.2025. Microsoft hat das kostenlose Consumer-ESU-Programm (nur Sicherheitsupdates) laut Berichten bis **Oktober 2027** verlängert. | [BleepingComputer](https://bleepingcomputer.com/news/microsoft/microsoft-quietly-extends-free-windows-10-esu-support-to-october-2027), [Help Net Security](https://www.helpnetsecurity.com/2026/06/26/microsoft-windows-10-free-security-updates-esu-program/) |
| Windows 11 24H2 Home/Pro | Support **beendet am 13.10.2026** | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-windows-11-24h2-home-and-pro-reached-end-of-support/) |
| Windows 11 24H2 Enterprise/Education | bis 12.10.2027 | ebd. |
| Windows 11 26H2 | seit September 2026 allgemein verfügbar, Consumer-Support bis Oktober 2029 | ebd. |
| Windows 11 25H2 | Nach Microsofts Regel 24 Monate für Home/Pro; Enddatum vor Release in der offiziellen Lifecycle-Seite prüfen | (nicht separat verifiziert) |
| .NET 10 (LTS) | Support bis **14.11.2028** | [.NET Support Policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core) |
| .NET 8 / .NET 9 | Support endet am 10.11.2026 – **nicht** als Basis verwenden | ebd. |
| ClamAV 1.4 (LTS) | EOL 15.08.2027, Signaturen bis 15.08.2028 | [ClamAV EOL Policy](https://docs.clamav.net/faq/faq-eol.html) |
| ClamAV 1.5.x | aktuelle Feature-Version (kein LTS); hier 1.5.4 getestet | ebd. |

**Konsequenzen für das Produkt**

* Unterstützt werden Windows 11 (aktuelle, von Microsoft noch versorgte Versionen) und Windows 10 22H2 **nur mit aktivem ESU**. Die Anwendung soll beim Start Build-Nummer und Updatestand anzeigen und ein nicht mehr versorgtes Betriebssystem als Risiko ausweisen („Schutz eingeschränkt“), statt es zu verschweigen.
* ClamAV-Versionen nach EOL werden von den offiziellen Signaturservern blockiert. Die Engine-Version muss also selbst aktualisiert werden; ein veraltetes ClamAV ist ein Statusfehler.

## 3. Technologievergleich und Entscheidungen

| Option | Bewertung | Entscheidung |
|---|---|---|
| **C# / .NET 10** | LTS bis 2028, speichersicher, sehr gute Windows-Integration (Dienste, Registry, Ereignisprotokoll, WMI, Named Pipes mit ACLs), gute Testbarkeit | **Hauptsprache** für Dienst, Kernlogik, CLI und GUI |
| **WPF** (.NET 10, Fluent-Theme) vs. **WinUI 3** | WPF: ausgereift, gut testbar, dunkles/helles Fluent-Design verfügbar. WinUI 3: modernerer Stack, aber komplexeres Deployment (Windows App SDK). | **WPF** mit MVVM, damit die Oberfläche nur ViewModels aus echtem Backend zeigt. Entscheidung in Phase 4 nochmals prüfen. |
| Native Windows-APIs (P/Invoke) | `WinVerifyTrust` (Authenticode), Task-Scheduler-COM, `ReadDirectoryChangesW`, USN-Journal, ETW, AMSI | gezielt über kleine, getestete Wrapper |
| Rust / C++ | Nur sinnvoll für eigene Parser mit hohem Risiko. Wir parsen selbst nur ZIP-Verzeichnisse (BCL) und später PE-Header. | **vorerst nicht nötig**; PE-Analyse ggf. mit einer gepflegten, speichersicheren Bibliothek |
| **ClamAV (`clamd`)** | Einzige verbreitete, gepflegte Open-Source-Engine mit laufend aktualisierten Signaturen, Archiv- und Formatunterstützung, offizieller Windows-Build. GPLv2. Erkennungsleistung bei aktueller Windows-Malware geringer als bei kommerziellen Engines – das wird nicht beschönigt. | **Primäre Signatur-Engine**, angesprochen als **separater Prozess** über das dokumentierte TCP-Protokoll (`INSTREAM`) |
| libclamav direkt einbinden | Parser-Absturz reißt die App mit; Linken mit GPL-Code betrifft die Lizenz des Gesamtprodukts | **abgelehnt** |
| **Microsoft Defender** | Auf fast allen Systemen vorhanden und deutlich stärker als ClamAV. Unterstützte Schnittstellen: `MpCmdRun.exe` (On-Demand-Scan einer Datei) und **AMSI** (`AmsiScanBuffer`) für Skriptinhalte. | **Zweite, unabhängige Engine** (Scanmodus 7) und Statusquelle. UScan deaktiviert Defender nie. |
| Kernel-Minifilter für Echtzeit-Blockierung | Ohne signierten Treiber (EV-Zertifikat, Microsoft-Signatur) nicht umsetzbar; laut Auftrag ausgeschlossen | **nicht geplant**. Echtzeit-*Blockierung* bleibt Defender überlassen und wird so angezeigt. |
| Registrierung im Windows-Sicherheitscenter als AV-Produkt | Ist Mitgliedern des Microsoft-Virus-Initiative-Programms vorbehalten (ELAM/Zertifizierung) | **nicht geplant**; UScan läuft als ergänzender Scanner neben Defender und gerät so nicht in Konflikt |

### Warum dieser Schnitt sicherer ist

1. Der risikoreichste Code (Parser für Hunderte Dateiformate) läuft in `clamd`, einem eigenen Prozess unter einem eigenen, niedrig privilegierten Dienstkonto.
2. UScan selbst parst nur das ZIP-Zentralverzeichnis über die .NET-Standardbibliothek und fängt Formatfehler kontrolliert ab.
3. Der Client akzeptiert standardmäßig nur Loopback-Adressen, damit keine Dateiinhalte versehentlich das Gerät verlassen.

## 4. Ein bei der Analyse gefundenes ClamAV-Verhalten

Mit ClamAV 1.5.4 nachgestellt (siehe `docs/06-TESTERGEBNISSE.md`):

* Verschachtelte Archive über `MaxRecursion` und Archive mit mehr als `MaxFiles` Einträgen werden mit `AlertExceedsMax yes` korrekt als `Heuristics.Limits.Exceeded.*` gemeldet.
* **Ein ZIP-Eintrag größer als `MaxFileSize` wird dagegen still auf `MaxFileSize` gekürzt und mit `OK` beantwortet** (Debug-Log: `cli_unzip: trimming output size to maxfilesize`).

Ein „OK“ von ClamAV bedeutet also nicht immer „vollständig geprüft“. UScan liest deshalb das ZIP-Zentralverzeichnis selbst und stuft solche Fälle als **„Unvollständig geprüft“** ein. Dafür gibt es einen Regressionstest.
