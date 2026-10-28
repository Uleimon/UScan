# 10 – Bekannte Probleme, Einschränkungen und Roadmap

## Bekannte Einschränkungen (Stand 0.5.0)

1. **Kein blockierender Echtzeitschutz.** Die Überwachung scannt nach der Änderung; eine Datei kann vorher geöffnet oder ausgeführt werden. Lösung wäre ein signierter Kernel-Minifilter-Treiber – bewusst nicht Teil dieses Projekts.
2. **Kein privilegierter Dienst.** UScan läuft als Benutzer. Dateien ohne Leserecht (z. B. andere Profile, Teile von `C:\Windows`) werden als Fehler gemeldet; ein „vollständiger Scan“ ist deshalb nur so vollständig wie die Rechte des Benutzers. Als Administrator gestartet werden mehr Dateien erreicht.
3. **Quarantäne im Benutzerprofil.** Schadsoftware mit Benutzerrechten könnte Quarantäne-Objekte löschen (Manipulation würde beim Wiederherstellen erkannt). Der Schlüssel liegt neben dem Objekt – die Verschlüsselung macht Dateien unschädlich, sie schützt sie nicht vor Einsicht.
4. **Erkennungsleistung hängt an ClamAV.** ClamAV erkennt aktuelle Windows-Malware deutlich schlechter als kommerzielle Engines. Die Defender-Zweitmeinung prüft nur Dateien, die ClamAV oder die Heuristik bereits gemeldet haben – sie findet also nichts zusätzlich, was beide übersehen.
5. **Heuristik ist absichtlich zurückhaltend.** Schwelle 60 aus mehreren Merkmalen, Signatur senkt die Punktzahl stark. Unsignierte, gepackte Programme von kleinen Herstellern können trotzdem als „verdächtig“ erscheinen.
6. **Echtzeitstatus anderer Antivirenprogramme** ist nicht zuverlässig lesbar (Windows-Sicherheitscenter liefert dafür kein dokumentiertes Feld); UScan zeigt dann „unbekannt“ und damit „Schutz eingeschränkt“.
7. **Massenänderungs-Hinweis** kennt den verursachenden Prozess nicht und stoppt nichts.
8. **Überwachung** läuft nur, solange Oberfläche oder `uscan watch` geöffnet sind; kein Autostart von UScan selbst.
9. **Mischsprache:** Gründe in der Statusanzeige, Protokolleinträge und einige Fehlermeldungen aus dem Kern sind englisch, die Oberfläche ist deutsch.
10. **Oberfläche:** Bedienung, Kontraste und Screenreader wurden nicht systematisch geprüft; die CI startet die Oberfläche nur und macht ein Bildschirmfoto.
11. **Programm-Updates** haben keinen Download-Client und keine Root/Targets-Schlüsseltrennung.
12. **Installer ohne Authenticode-Signatur** und ohne ClamAV: Setup (Inno Setup) und ZIP werden von der Release-CI gebaut, die Dateien sind aber nicht signiert – Windows SmartScreen kann beim ersten Start warnen. ClamAV muss separat installiert werden.
13. **Windows 10:** getestet wird in der CI nur auf `windows-latest` (Windows Server 2022/2025). Windows 10 22H2 und Windows 11 Client wurden nicht automatisiert getestet.
14. **Leistungszahlen** stammen aus einer Test-Signaturdatenbank mit einer Signatur; mit der offiziellen Datenbank sind Speicherbedarf und Dauer von clamd deutlich höher.

## Roadmap (Vorschlag, nach Nutzen geordnet)

| # | Vorhaben | Nutzen |
|---|---|---|
| 1 | Installer um ClamAV-Einrichtung (GPL-Pflichten beachten) und Autostart der Überwachung im Infobereich erweitern; Code-Signing-Zertifikat | einfache Installation, Überwachung läuft dauerhaft |
| 2 | Optionaler Windows-Dienst für Scans mit Systemrechten, Quarantäne unter `%ProgramData%` mit ACL (nur SYSTEM/Admins), Named-Pipe mit Prüfung der Client-Identität | vollständige Scans, Quarantäne vor Benutzer-Malware geschützt |
| 3 | Zeitgesteuerte Scans über die Windows-Aufgabenplanung | regelmäßige Prüfung ohne Zutun |
| 4 | AMSI-Scan von Skriptinhalten über Defender, ETW-Prozessereignisse (Admin) | bessere Erkennung dateiloser Angriffe |
| 5 | Opt-in-Hash-Reputation (nur SHA-256, ausdrückliche Zustimmung) | Zusatzinfo bei unbekannten Programmen |
| 6 | Vollständige Lokalisierung (Deutsch/Englisch) | einheitliche Sprache |
| 7 | Barrierefreiheit (Automation-Namen, Kontrast-Messung), UI-Automatisierungstests | Qualität der Oberfläche |
| 8 | Update-Client mit TUF-ähnlicher Schlüsselhierarchie, Authenticode-Signatur | sichere automatische Updates |
| 9 | Tests auf Windows 10 22H2 und Windows 11 (self-hosted Runner oder VM) | belastbare Plattformaussage |
| 10 | Messreihe mit offizieller ClamAV-Datenbank und Fehlalarm-Korpus gängiger Software | echte Leistungs- und Fehlalarmzahlen |
