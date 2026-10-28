# 05 – Funktionsstatus: implementiert und nicht implementiert

Stand 28.10.2026, Version 0.5.0. „Getestet“ heißt: automatisierter Test vorhanden und in diesem Stand tatsächlich ausgeführt – auf Linux (ClamAV 1.5.4) und in der Windows-CI (`windows-latest`, ClamAV 1.5.4, echter Microsoft Defender). Zahlen und Einzelergebnisse: [06](06-TESTERGEBNISSE.md).

Legende: ✅ implementiert und getestet · 🟠 implementiert, nur teilweise automatisiert getestet · ❌ nicht implementiert

## A – Signaturerkennung

| Funktion | Status |
|---|---|
| Scan über ClamAV (`clamd`, INSTREAM, nur Loopback) | ✅ |
| Engine-/Datenbankversion und -alter, „Update erforderlich“ ab Höchstalter (Standard 3 Tage) | ✅ |
| Signatur-Update über `freshclam`, Auswertung der dokumentierten Fehlercodes, Protokoll | ✅ (Fehlercodes mit simuliertem Prozess getestet; echter Download nicht in der CI) |
| Validierung beschädigter Datenbanken | 🟠 übernimmt `freshclam` (Signaturprüfung, Code 54); UScan meldet nur das Ergebnis |

## B – Heuristik

| Funktion | Status |
|---|---|
| PE-Analyse: W+X-Sektionen, Packer-Sektionsnamen, Entropie, Einsprungpunkt, dynamisches Laden, Injektions- und Keylogger-Importe, Zeitstempel, Overlay | ✅ |
| Kontext: doppelte Endung, Ort (Temp, AppData, Downloads), Authenticode-Status (vertrauenswürdig −50) | ✅ |
| Skripte: PowerShell, VBS/VBE, JS/JSE, WSF, HTA, BAT/CMD (Download-Cradles, Verschleierung, Schattenkopien löschen, Wiederherstellung abschalten, Dropper-Kombinationen) | ✅ |
| Office-Makros (OOXML): vbaProject, AutoOpen, Shell/CreateObject, Endung-/Inhalt-Widerspruch, Remote-Templates | ✅ |
| Ergebnis höchstens „Verdächtig“, Schwelle 60 aus ≥ 2 Merkmalen, Begründung je Merkmal | ✅ |
| Fehlalarm-Messung gegen `C:\Windows\System32\*.exe` und Windows-eigene Skripte | ✅ (Windows-CI, Ergebnis in 06) |
| Altes OLE-Office-Format (.doc/.xls) | ❌ – ClamAV-Signaturen decken diese Dateien weiterhin ab |

## C – Verhalten / Überwachung

| Funktion | Status |
|---|---|
| Nachscan neuer/geänderter/umbenannter Dateien in gewählten Ordnern, inkl. neu angelegter Unterordner | ✅ (echter Dateisystemtest) |
| Hinweis bei Massenänderungen (mögliches Ransomware-Anzeichen) | ✅ – nur Hinweis, kein Prozessbezug, kein Stoppen |
| Verlorene Ereignisse (Pufferüberlauf, Warteschlange voll) zählen und melden | ✅ |
| Autostart-Änderungen erkennen (Baseline-Vergleich) | ✅ |
| **Blockieren** von Dateizugriffen / Ausführung | ❌ bewusst nicht (bräuchte Kernel-Minifilter). Defender bleibt zuständig. |
| Prozessketten, Speicher-Scan laufender Prozesse, AMSI-Anbindung | ❌ |

## D – Archive

| Funktion | Status |
|---|---|
| Archive über ClamAV, verschachtelte ZIPs | ✅ (ZIP getestet; weitere Formate von ClamAV unterstützt, von uns **nicht** getestet) |
| Grenzen für Rekursion, Anzahl, Größe, Kompressionsverhältnis → „Unvollständig“ | ✅ |
| Defekte Archive | ✅ |
| Nicht unterstützte Formate ausweisen | ❌ (ClamAV meldet nicht, ob es ein Format verstanden hat) |

## E – Hash / Reputation

| Funktion | Status |
|---|---|
| SHA-256 jeder gescannten Datei (im selben Lesedurchgang) | ✅ |
| Fehlalarm zulassen (nur exakt dieser SHA-256, mit Begründung, protokolliert) | ✅ (CLI `allow`) |
| Online-Reputationsdienst | ❌ nicht implementiert – es gibt keinerlei Hash-Abfragen ins Internet |

## F – Rootkit / Manipulation

| Funktion | Status |
|---|---|
| Dienste: Registry gegen Service Control Manager abgleichen (nur Hinweis) | ✅ |
| Rootkit-Scan, Boot-Sektor-Prüfung, Offline-Scan | ❌ – Empfehlung: Microsoft Defender Offline |

## Quarantäne

| Funktion | Status |
|---|---|
| Verschlüsselt (AES-256-GCM), verifizierte Kopie vor dem Löschen, Hash-Gleichheit mit Scan | ✅ |
| Schutzliste für Systemordner, nur mit Admin-Bestätigung | ✅ |
| Wiederherstellung mit erneutem Scan, kein Überschreiben, keine Reparse-Points im Ziel | ✅ |
| Endgültiges Löschen nur mit Bestätigung | ✅ |
| Unversehrtheit prüfen | ✅ |

## System- und Autostart-Analyse

| Funktion | Status |
|---|---|
| Run/RunOnce (HKLM/HKCU, WOW6432Node), Startup-Ordner (inkl. .lnk-Ziel), Winlogon Shell/Userinit, IFEO Debugger, AppInit_DLLs | ✅ |
| Dienste und geplante Aufgaben | ✅ |
| Authenticode-Prüfung (eingebettet und über Windows-Kataloge), Herausgeber, SHA-256 | ✅ |
| Beobachtungen (unsigniert, ungültige Signatur, Datei fehlt, benutzerbeschreibbarer Ort, versteckte Aufgabe, Dienst nur in der Registry) – ausdrücklich keine Urteile; bei rundll32/regsvr32/Skript-Hosts wird die eigentliche Zieldatei geprüft | ✅ |
| Browser-Erweiterungen, WMI-Event-Abonnements, COM-Hijacking | ❌ |

## Scan-Modi

| Modus | Status |
|---|---|
| Schnellscan (Desktop, Downloads, Temp, AppData-Roaming, Startup-Ordner bis Tiefe 4 + alle Autostart-Ziele) | ✅ |
| Vollständiger Scan (alle festen Laufwerke) | ✅ |
| Autostart-Scan | ✅ |
| Benutzerdefiniert (Dateien/Ordner) | ✅ |
| Zweitmeinung durch Microsoft Defender bei Funden | ✅ (Windows-CI erkennt EICAR über Defender) |
| Offline-/Boot-Scan | ❌ – wird nirgends als verfügbar angezeigt |
| Zeitgesteuerte Scans | ❌ (Windows-Aufgabenplanung mit `uscan scan quick` ist möglich, wird aber nicht von UScan eingerichtet) |

## Oberfläche (WPF)

| Funktion | Status |
|---|---|
| Übersicht mit 7 Zuständen; Farbe Grün nur bei „Geschützt“ | ✅ (ViewModel-Tests: ohne Engine nie grün, offener Fund → rot) |
| Scannen mit echtem Fortschritt („Gesamtzahl wird noch ermittelt“, bis gezählt ist), Abbruch, Ergebnisliste mit Begründung | ✅ |
| Quarantäne verwalten, Autostart-Liste, Überwachung, Protokoll, Info | 🟠 Programmlogik getestet; Bedienung nur per Start-Test und Bildschirmfoto in der CI geprüft |
| Hell/Dunkel (folgt Windows-Einstellung, umschaltbar) | 🟠 manuell zu prüfen |
| Screenreader-/Kontrastprüfung (WCAG AA) | ❌ nicht geprüft |

## Updates

| Funktion | Status |
|---|---|
| Signierte Programm-Updates (Manifest + ECDSA P-256), Downgrade-/Replay-/Freeze-Schutz | ✅ |
| Installation nebeneinander, Selbsttest, Rollback | ✅ |
| Automatischer Download/Update-Server | ❌ – Updates werden als Dateien übergeben (`uscan update program`) |
| Installer (MSI/MSIX), Authenticode-Signatur der eigenen Binärdateien | ❌ |

## Datenschutz

| Funktion | Status |
|---|---|
| Keine Telemetrie, keine Datei-Uploads, alles lokal | ✅ (keinerlei Netzwerkcode außer clamd-Loopback; Test für Loopback-Erzwingung) |
| Protokolle und Berichte nur im Benutzerprofil, Rotation | ✅ |
