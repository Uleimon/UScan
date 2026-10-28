# UScan – Malware-Scanner für Windows 10/11

UScan ist ein überprüfbarer, mehrschichtiger Malware-Scanner für Windows 10/11 (x64) mit Oberfläche (WPF) und Kommandozeile. Er nutzt ClamAV als Signatur-Engine, eigene Heuristiken mit Begründung, Microsoft Defender als Zweitmeinung, eine verschlüsselte Quarantäne, ein Autostart-Inventar mit Signaturprüfung und eine Dateiüberwachung, die geänderte Dateien nachscannt.

> **Ehrliche Einordnung:** UScan **ergänzt** Microsoft Defender, ersetzt ihn aber nicht. UScan hat keinen Kernel-Treiber und kann deshalb Dateizugriffe **nicht blockieren**; die Überwachung prüft Dateien kurz *nach* einer Änderung. Den blockierenden Echtzeitschutz liefert Defender, den UScan nie abschaltet. Was genau implementiert und getestet ist, steht in [docs/05-FUNKTIONSSTATUS.md](docs/05-FUNKTIONSSTATUS.md).

## Funktionen (implementiert und automatisiert getestet)

| Bereich | Was UScan macht |
|---|---|
| Signaturen | Scan über ClamAV (`clamd`, nur Dateiinhalt per INSTREAM, nie Pfade); Signatur-Updates über `freshclam` mit Auswertung der Fehlercodes |
| Archive | Erkennung in verschachtelten Archiven; Grenzen gegen ZIP-Bomben; „unvollständig geprüft“ statt falschem „sauber“ |
| Heuristik | PE-Dateien (Sektionen, Entropie, Importe, Packer, Signatur, Ort), Skripte (PowerShell, VBS, JS, Batch, HTA) und Office-Makros; Ergebnis höchstens „verdächtig“, immer mit Begründung |
| Zweitmeinung | Microsoft Defender (`MpCmdRun -DisableRemediation`) prüft jeden Fund nach, ohne selbst etwas zu verändern |
| Quarantäne | AES-256-GCM-verschlüsselt, Original wird erst nach verifizierter Kopie entfernt, Wiederherstellung nur nach erneutem Scan und ohne Überschreiben, Schutzliste für Systemordner |
| System | Autostart (Registry, Startup-Ordner, Winlogon, IFEO, AppInit), Dienste, geplante Aufgaben – mit Authenticode-/Katalogsignatur und Erkennung von Änderungen |
| Überwachung | Nachscan neuer/geänderter Dateien in gewählten Ordnern, Hinweis bei Massenänderungen (mögliches Ransomware-Anzeichen), Autostart-Änderungen |
| Scan-Modi | Schnell, Vollständig, Autostart, Ordner/Dateien |
| Status | Sieben Zustände; „Geschützt“ nur, wenn jede Voraussetzung nachweislich erfüllt ist |
| Updates | Programm-Updates nur mit ECDSA-P-256-signiertem Manifest (Downgrade-/Freeze-Schutz), Installation nebeneinander mit Selbsttest und Rollback |
| Datenschutz | Alles lokal, keine Telemetrie, keine Datei-Uploads |

## Dokumentation

1. [Analyse, Supportstatus, Technologiewahl](docs/01-ANALYSE-UND-PLATTFORM.md)
2. [Architektur](docs/02-ARCHITEKTUR.md)
3. [Bedrohungsmodell](docs/03-BEDROHUNGSMODELL.md)
4. [Implementierungsplan und Abnahme](docs/04-IMPLEMENTIERUNGSPLAN.md)
5. [Funktionsstatus: implementiert / nicht implementiert](docs/05-FUNKTIONSSTATUS.md)
6. [Tests, Messungen und tatsächliche Ergebnisse](docs/06-TESTERGEBNISSE.md)
7. [Lizenzen](docs/07-LIZENZEN.md)
8. [Installation, Start, Bedienung, Updates](docs/08-INSTALLATION-UND-BEDIENUNG.md)
9. [Schlüsselverwaltung für Programm-Updates](docs/09-SCHLUESSELVERWALTUNG.md)
10. [Bekannte Probleme und Roadmap](docs/10-BEKANNTE-PROBLEME-UND-ROADMAP.md)

## Schnellstart (Windows)

**Fertiges Programm:** Unter [Releases](https://github.com/Uleimon/UScan/releases) liegen `UScan-<Version>-Setup.exe` (Installation ohne Administratorrechte, Startmenü- und Desktop-Verknüpfung) und eine ZIP-Datei zum Entpacken. .NET muss dafür nicht installiert sein, ClamAV schon (siehe `LIESMICH.txt` im Paket bzw. [docs/08](docs/08-INSTALLATION-UND-BEDIENUNG.md)).

**Aus dem Quellcode:**

1. [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) und [ClamAV für Windows](https://www.clamav.net/downloads) installieren, Signaturen mit `freshclam` laden und `clamd` starten (Schritt für Schritt in [docs/08](docs/08-INSTALLATION-UND-BEDIENUNG.md)).
2. Repository holen und starten:
   ```powershell
   git clone https://github.com/Uleimon/UScan.git
   cd UScan
   dotnet run --project src/UScan.Desktop            # Oberfläche
   dotnet run --project src/UScan.Cli -f net10.0-windows -- status   # Kommandozeile
   ```

## Bauen und testen

```bash
dotnet build
dotnet test     # Integrationstests starten einen eigenen clamd mit Test-Signatur; ohne ClamAV werden sie als übersprungen gemeldet
```

Die GitHub-Actions-CI baut und testet auf Linux und Windows (mit echtem ClamAV, Defender und Windows-APIs) und startet die Oberfläche einmal zur Kontrolle.

## Testdateien

Tests verwenden ausschließlich harmlose Daten und den [EICAR-Teststandard](https://www.eicar.org/download-anti-malware-testfile/). Es wird keine echte Malware heruntergeladen oder ausgeführt.
