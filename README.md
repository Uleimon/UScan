# UScan – Anti-Malware-Scanner für Windows (in Entwicklung)

UScan soll eine überprüfbare, mehrschichtige Anti-Malware-Anwendung für Windows 10/11 (x64) werden. Dieser Stand ist **Phase 1 plus der plattformneutrale Teil von Phase 2**: Analyse, Architektur, Bedrohungsmodell und ein kleiner, getesteter Scan-Kern mit Kommandozeile.

> **Wichtig:** UScan ist in diesem Stand **kein** Ersatz für Microsoft Defender und bietet **keinen** Echtzeitschutz, keine Quarantäne und keine Oberfläche. Was implementiert ist und was nicht, steht in [docs/05-FUNKTIONSSTATUS.md](docs/05-FUNKTIONSSTATUS.md).

## Was heute funktioniert (getestet)

* On-Demand-Scan von Dateien/Ordnern über ClamAV (`clamd`, INSTREAM-Protokoll)
* SHA-256 jeder geprüften Datei im selben Lesedurchgang
* Ehrliche Ergebnisse: *Infiziert*, *Verdächtig*, *Unvollständig geprüft*, *Übersprungen*, *Fehler*, *Ohne Befund*
* Archive: Erkennung in (verschachtelten) ZIPs, Grenzen gegen ZIP-Bomben, kontrollierte Behandlung defekter Archive
* Keine Verfolgung von Symlinks/Reparse-Points, Abbruch, Engine-Ausfall, Zugriffsfehler
* Statuslogik, die nie „Geschützt“ meldet, wenn etwas fehlt
* JSON-Bericht, definierte Exit-Codes

## Dokumentation

1. [Analyse, Supportstatus, Technologiewahl](docs/01-ANALYSE-UND-PLATTFORM.md)
2. [Architektur](docs/02-ARCHITEKTUR.md)
3. [Bedrohungsmodell](docs/03-BEDROHUNGSMODELL.md)
4. [Implementierungsplan und Abnahmekriterien](docs/04-IMPLEMENTIERUNGSPLAN.md)
5. [Funktionsstatus](docs/05-FUNKTIONSSTATUS.md)
6. [Teststrategie und Testergebnisse](docs/06-TESTERGEBNISSE.md)
7. [Lizenzen](docs/07-LIZENZEN.md)

## Bauen und testen

Voraussetzungen: .NET SDK 10, optional ClamAV ≥ 1.4 (für Integrationstests und echte Scans).

```bash
dotnet build
dotnet test          # Integrationstests starten einen eigenen clamd; ohne ClamAV werden sie übersprungen
```

Windows: ClamAV über das offizielle Installationspaket von clamav.net installieren und bei Bedarf
`set USCAN_CLAMD=C:\Program Files\ClamAV\clamd.exe` setzen.

## Benutzen (Kommandozeile)

1. ClamAV installieren, `freshclam` ausführen (offizielle Signaturen), `clamd` mit [config/clamd.conf.example](config/clamd.conf.example) starten.
2. ```bash
   dotnet run --project src/UScan.Cli -- status
   dotnet run --project src/UScan.Cli -- scan C:\Users\me\Downloads --json bericht.json
   ```

Exit-Codes: `0` nichts gefunden · `1` Funde · `2` unvollständig/Fehler/abgebrochen · `3` Engine nicht erreichbar · `64` falscher Aufruf.

## Testdateien

Tests verwenden ausschließlich harmlose Daten und den [EICAR-Teststandard](https://www.eicar.org/download-anti-malware-testfile/). Es wird keine echte Malware heruntergeladen oder ausgeführt.
