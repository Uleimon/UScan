# 08 – Installation, Start, Bedienung und Updates

## 0. Fertiges Paket (empfohlen)

Unter [Releases](https://github.com/Uleimon/UScan/releases) gibt es zu jeder Version:

* `UScan-<Version>-Setup.exe` – installiert pro Benutzer nach `%LOCALAPPDATA%\Programs\UScan` (keine Administratorrechte nötig), legt Startmenü- und optional Desktop-Verknüpfung an, bringt eine Deinstallation mit. Daten unter `%LOCALAPPDATA%\UScan` bleiben beim Deinstallieren erhalten.
* `UScan-<Version>-win-x64.zip` – dasselbe zum Entpacken, ohne Installation.
* `SHA256SUMS.txt` – Prüfsummen.

Beide enthalten `UScan.exe` (Oberfläche), `uscan-cli.exe` (Kommandozeile; im Paket umbenannt, weil Windows `uscan.exe` und `UScan.exe` nicht unterscheidet) und `LIESMICH.txt`. Die .NET-Laufzeit ist eingebaut; **ClamAV ist nicht enthalten** und muss wie in Abschnitt 1–2 eingerichtet werden. Die Dateien sind nicht Authenticode-signiert, Windows SmartScreen kann beim ersten Start warnen.

Gebaut werden die Pakete von `.github/workflows/release.yml` (bei einem Tag `v*`). Die CI testet dabei das veröffentlichte Programm selbst: Oberflächen-Selbsttest, EICAR-Fund der Kommandozeile mit echtem `clamd`, stille Installation, Start und Deinstallation.

Neue Version veröffentlichen: Version in `Directory.Build.props` erhöhen, dann entweder `git tag v0.5.1 && git push origin v0.5.1` oder auf GitHub unter *Releases → Draft a new release* den Tag `v0.5.1` neu anlegen und veröffentlichen. Die CI hängt Setup, ZIP und Prüfsummen nach etwa 5 Minuten an das Release an.

Ohne Paket wird UScan aus dem Quellcode gebaut (Abschnitt 3). Alle Schritte laufen mit normalen Benutzerrechten, außer der ClamAV-Installation.

## 1. Voraussetzungen (Windows 10 22H2 oder Windows 11, x64)

1. **.NET 10 SDK** von https://dotnet.microsoft.com/download/dotnet/10.0 installieren. Prüfen: `dotnet --version` zeigt `10.0.x`.
2. **Git** (optional, sonst das Repository als ZIP von GitHub herunterladen).
3. **ClamAV für Windows** (getestet: 1.5.4) über den offiziellen Installer von https://www.clamav.net/downloads – die Datei mit **`win.x64`** im Namen. Die ARM64-Version startet auf normalen PCs mit „keine gültige Anwendung für diese Betriebssystemplattform“. Standardpfad: `C:\Program Files\ClamAV`.

## 2. ClamAV einrichten (einmalig, PowerShell als Administrator)

```powershell
cd "C:\Program Files\ClamAV"
copy conf_examples\freshclam.conf.sample freshclam.conf
copy conf_examples\clamd.conf.sample clamd.conf
notepad freshclam.conf   # Zeile "Example" löschen oder mit # auskommentieren
notepad clamd.conf       # Zeile "Example" auskommentieren und die Werte unten eintragen
.\freshclam.exe          # lädt die offiziellen Signaturen (ca. 300 MB)
```

Empfohlene Werte in `clamd.conf` (passen zu den UScan-Standardeinstellungen; Vorlage: [config/clamd.conf.example](../config/clamd.conf.example)):

```
TCPSocket 3310
TCPAddr 127.0.0.1
StreamMaxLength 100M
MaxFileSize 100M
MaxScanSize 400M
MaxFiles 10000
AlertExceedsMax yes
AlertEncrypted yes
```

`clamd` starten (Fenster offen lassen) oder als Dienst einrichten:

```powershell
.\clamd.exe                 # Vordergrund, zum Ausprobieren
.\clamd.exe --install-service ; Start-Service clamd    # dauerhaft als Windows-Dienst
```

`clamd` braucht mit offiziellen Signaturen etwa 1–1,5 GB Arbeitsspeicher und 20–60 s zum Laden.

## 3. UScan holen, bauen, starten

```powershell
git clone https://github.com/Uleimon/UScan.git
cd UScan
dotnet build -c Release
dotnet run -c Release --project src\UScan.Desktop          # Oberfläche
dotnet run -c Release --project src\UScan.Cli -f net10.0-windows -- status    # Kommandozeile
```

Fertige Programme liegen danach unter `src\UScan.Desktop\bin\Release\net10.0-windows\UScan.exe` und `src\UScan.Cli\bin\Release\net10.0-windows\uscan.exe`. Eine eigenständige Version (ohne installiertes .NET auf dem Zielrechner):

```powershell
dotnet publish src\UScan.Desktop -c Release -r win-x64 --self-contained -o publish\UScan
dotnet publish src\UScan.Cli -c Release -f net10.0-windows -r win-x64 --self-contained -o publish\uscan-cli   # eigener Ordner: Windows unterscheidet uscan.exe und UScan.exe nicht
```

## 4. Oberfläche

| Seite | Inhalt |
|---|---|
| Übersicht | Gesamtstatus (Farbe Grün nur bei „Geschützt“), Gründe, Engine, Signaturen, Echtzeitschutz (Defender), Dateiüberwachung, Quarantäne, offene Funde; „Signaturen aktualisieren“ |
| Scannen | Schnell, Vollständig, Autostart, Ordner; Fortschritt, Abbruch; Funde mit Begründung (Tooltip), Auswahl in Quarantäne |
| Quarantäne | Wiederherstellen (mit Nachscan), Unversehrtheit prüfen, endgültig löschen |
| Autostart | Alle Einträge mit Signatur; „Änderungen seit letzter Prüfung“ |
| Überwachung | Ordner wählen, Starten/Beenden, Ereignisse |
| Protokoll | Letzte 500 Ereignisse |
| Info | Version, Datenordner, was UScan kann und was nicht, Hell/Dunkel |

Die Überwachung läuft nur, solange die Oberfläche (oder `uscan watch`) geöffnet ist.

## 5. Kommandozeile

```
uscan status
uscan scan quick | full | autostart
uscan scan C:\Users\me\Downloads [--quarantine] [--json bericht.json]
uscan quarantine list | add <Datei> | restore <ID> | delete <ID> | verify <ID>
uscan allow <Datei> --reason "Fehlalarm: eigenes Tool"
uscan inventory [--changes]
uscan watch [<Ordner> …]
uscan update signatures
uscan log
uscan settings
```

Rückfragen (Quarantäne, Löschen, Wiederherstellen, Zulassen) verlangen die Eingabe `ja`. In Skripten muss `--yes` ausdrücklich angegeben werden; ohne Eingabemöglichkeit und ohne `--yes` wird abgelehnt.

Exit-Codes: `0` ok · `1` Funde/offene Funde · `2` unvollständig, abgelehnt oder abgebrochen · `3` Engine nicht erreichbar · `64` falscher Aufruf.

## 6. Einstellungen

Datei `%LOCALAPPDATA%\UScan\settings.json` (fehlt sie, gelten Standardwerte; `uscan settings` zeigt die aktiven Werte). Beispiel:

```json
{
  "clamdHost": "127.0.0.1",
  "clamdPort": 3310,
  "maxStreamMb": 100,
  "archiveMaxFileMb": 100,
  "archiveMaxScanMb": 400,
  "archiveMaxFiles": 10000,
  "maxSignatureAgeDays": 3,
  "parallelism": 2,
  "heuristicsEnabled": true,
  "defenderSecondOpinion": true,
  "freshclamPath": "C:\\Program Files\\ClamAV\\freshclam.exe",
  "watchFolders": [ "C:\\Users\\me\\Downloads" ],
  "autostartCheckMinutes": 15
}
```

Die Archivgrenzen **müssen** zu `clamd.conf` passen, sonst kann UScan stille Kürzungen nicht erkennen. Eine fehlerhafte Datei wird gemeldet und nicht überschrieben.

## 7. Daten und Deinstallation

Alles liegt in `%LOCALAPPDATA%\UScan`: `reports\` (Scanberichte), `logs\` (Ereignisprotokoll), `quarantine\` (verschlüsselte Objekte), `baselines\` (Autostart-Ausgangszustand), `allowed.json` (zugelassene Fehlalarme). Zum Entfernen: Programmordner und diesen Ordner löschen – vorher Quarantäne-Objekte bei Bedarf wiederherstellen.

## 8. Updates

* **Signaturen:** `uscan update signatures` oder Schaltfläche in der Übersicht (ruft `freshclam` auf). Alternativ den Dienst `freshclam` von ClamAV nutzen.
* **Programm (Quellcode):** `git pull` und neu bauen.
* **Programm (signiertes Paket):** `uscan update program --manifest uscan-0.6.0.json --signature uscan-0.6.0.json.sig --package uscan-0.6.0.zip --install-root C:\Tools\UScan`. Voraussetzung: der öffentliche Release-Schlüssel liegt als `keys\<keyId>.pem` neben `uscan.exe` ([09](09-SCHLUESSELVERWALTUNG.md)). Ohne Schlüssel lehnt UScan jedes Update ab.

## 9. Fehlerbehebung

| Meldung | Ursache / Lösung |
|---|---|
| „Scan-Engine NICHT erreichbar“ | `clamd` läuft nicht oder anderer Port. `Get-Service clamd` bzw. Fenster prüfen, Port in `settings.json` |
| „Keine offizielle Signaturdatenbank erkannt“ | `freshclam` noch nicht gelaufen |
| „freshclam failed: network connection problem (exit code 52)“ | Internet/Proxy prüfen; Proxy in `freshclam.conf` eintragen |
| `freshclam.exe`/`clamd.exe`: „keine gültige Anwendung für diese Betriebssystemplattform“ | Falsche ClamAV-Version (ARM64). `win.x64`-Paket installieren |
| ClamAV in anderem Ordner (z. B. `E:\ClamAV`) | In `settings.json` `"freshclamPath": "E:\\ClamAV\\freshclam.exe"` eintragen; `clamd` wird über TCP angesprochen, sein Ordner ist egal |
| „Echtzeitschutz: unbekannt“ mit Hinweis auf anderes Antivirenprogramm | Defender ist passiv, weil ein anderes Produkt registriert ist; dessen Status kann UScan nicht lesen |
| Funde „Unvollständig geprüft“ | Archiv überschreitet die Grenzen; Grenzen in `clamd.conf` **und** `settings.json` erhöhen oder Datei einzeln prüfen |
