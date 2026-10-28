# 03 – Bedrohungsmodell und Sicherheitsgrenzen

Methode: STRIDE je Komponente aus `02-ARCHITEKTUR.md`. Spalte „Status“: ✅ umgesetzt und getestet, 🟡 geplant, ⚠ Restrisiko.

## 1. Schützenswerte Güter

1. Dateien und Privatsphäre der Nutzer (Inhalte, Pfade, Hashes)
2. Integrität des Systems (keine Schäden durch Fehlalarme oder fehlerhafte Quarantäne)
3. Ehrlichkeit der Statusanzeige (ein falsches „Geschützt“ ist selbst ein Sicherheitsproblem)
4. Signaturdatenbank und Programmupdates
5. Quarantäne-Inhalte (enthalten Malware, dürfen nicht versehentlich ausgeführt oder wiederhergestellt werden)
6. Privilegien des Dienstes

## 2. Angreifer

* **A1 Schadhafte Datei** auf dem Datenträger (passiv, will Parser ausnutzen, Scan umgehen oder Ressourcen erschöpfen)
* **A2 Lokaler Prozess mit Benutzerrechten** (z. B. Malware, die bereits läuft)
* **A3 Netzwerkangreifer** (Update-Manipulation, Man-in-the-Middle)
* **A4 Lokaler Administrator / Kernel-Malware** – liegt **außerhalb** dessen, wovor eine Anwendung im Benutzermodus schützen kann

## 3. Bedrohungen und Gegenmaßnahmen

| # | Komponente | STRIDE | Bedrohung | Gegenmaßnahme | Status |
|---|---|---|---|---|---|
| T1 | Scan-Engine | E/D | Präparierte Datei nutzt Parserfehler in ClamAV aus | Parser läuft in separatem `clamd`-Prozess unter eigenem, gering privilegiertem Konto; Absturz → Engine-Fehler, kein falsches „sauber“ | ✅ Prozess-/Fehlertrennung · 🟡 Dienstkonto (Windows) |
| T2 | Archive | D | ZIP-Bombe, tiefe Verschachtelung, Millionen Einträge | `clamd`-Limits (`MaxFileSize`, `MaxScanSize`, `MaxRecursion`, `MaxFiles`, `MaxScanTime`) + `AlertExceedsMax`; UScan meldet `Incomplete`; eigene Prüfung des Zentralverzeichnisses mit Kompressionsverhältnis | ✅ (Tests T-INT-4…7) |
| T3 | Archive | T (Reporting) | ClamAV kürzt zu große ZIP-Einträge still und meldet „OK“ | `ZipLimitInspector` stuft auf „Unvollständig“ herab | ✅ Regressionstest |
| T4 | Archive | T | Gefälschte Größenangaben im ZIP-Verzeichnis | Nur Berichtsschutz; Durchsetzung erfolgt durch ClamAV-Limits. | ⚠ dokumentiert |
| T5 | Scanner | T/I | Symlink/Junction leitet Scan in fremde Bereiche oder erzeugt Endlosschleifen | Reparse-Points werden nie verfolgt und als „übersprungen“ gemeldet; Tiefenlimit | ✅ |
| T6 | Scanner | D | Datei wird während des Scans vergrößert | Stream-Limit wird beim Senden erneut geprüft → `Skipped` | ✅ |
| T7 | Scanner | R | Abbruch/Fehler wird als „sauber“ dargestellt | eigene Verdicts `Error`, `Incomplete`, `Skipped`; `FilesNotProcessed`; unbekannte Engine-Antwort → `Error` | ✅ |
| T8 | clamd-TCP | S/I/E | Lokaler Prozess verbindet sich mit `clamd` und nutzt `SCAN <pfad>` mit dessen Rechten | UScan nutzt nur `INSTREAM`; `clamd` bindet an 127.0.0.1 und läuft unter einem Konto ohne Zugriff auf Nutzerdaten | ✅ Client · 🟡 Konto-Härtung im Installer |
| T9 | clamd-TCP | D | Lokaler Prozess blockiert `clamd` mit Anfragen | `MaxThreads`/`MaxQueue`; UScan-Timeouts → `Error` statt Hängen | ✅ Timeout · ⚠ DoS durch A2 möglich |
| T10 | Client | I | Dateiinhalte werden versehentlich an entfernten Host gesendet | Nicht-Loopback-Hosts nur nach explizitem Opt-in | ✅ |
| T11 | Status | S | Oberfläche zeigt „Geschützt“, obwohl Engine aus/veraltet | `StatusEvaluator`: „Geschützt“ nur, wenn **jede** Voraussetzung positiv bekannt ist; fehlendes Echtzeitmodul → „Schutz eingeschränkt“ | ✅ (vollständige Negativtests) |
| T12 | Updates | T/S | Manipulierte Signaturen oder Programmpakete | CVD-Signaturprüfung durch `freshclam`; Programmupdates signiert (TUF-Prinzipien), Hash-Pinning, HTTPS | 🟡 |
| T13 | Updates | T | Downgrade-/Freeze-Angriff | Versionsnummer und Ablaufdatum in signierten Metadaten, Status „veraltet“ nach Höchstalter | 🟡 (Altersprüfung ✅) |
| T14 | IPC | E/S | Unprivilegierter Prozess sendet „Datei löschen“ an den Dienst | Pipe-ACL, Identität des Clients prüfen, destruktive Aktionen nur mit Bestätigung, Schutzliste für Systemdateien, nur Quarantäne-IDs statt freier Pfade | 🟡 |
| T15 | Quarantäne | T/E | Wiederherstellung über Symlink in Systemordner, Race zwischen Prüfung und Schreiben | Handle-basierte Operationen, Reparse-Prüfung der Zielkette, atomares Umbenennen, erneuter Scan | 🟡 |
| T16 | Quarantäne | D (Integrität) | Fehlalarm verschiebt Systemdatei → System startet nicht | Schutzliste, Standardaktion nie „Löschen“, Bestätigung, vollständige Wiederherstellung | 🟡 |
| T17 | Reputation | I | Hash-Abfrage verrät, welche Dateien jemand besitzt | Opt-in, nur Hash, keine Pfade, Hinweis im Dialog | 🟡 |
| T18 | Protokolle | I | Logs enthalten Benutzerpfade | lokal, nur für Admin/Benutzer lesbar, Aufbewahrungsdauer, keine Übertragung | 🟡 |
| T19 | Selbstschutz | T | Malware beendet UScan | Dienst-Wiederanlauf, Status „Unbekannt/eingeschränkt“ in der GUI, wenn der Dienst nicht antwortet. Echter Selbstschutz gegen Admin-Malware ist ohne Kernel-Komponente (PPL/ELAM) **nicht möglich**. | 🟡 / ⚠ |
| T20 | Gesamt | – | Kernel-Rootkit verbirgt Dateien/Prozesse vor Benutzermodus-APIs | Nicht lösbar im Benutzermodus. Empfehlung: Microsoft Defender Offline-Scan. Inventar-Abgleich (z. B. Dienste via SCM vs. Registry) liefert nur **Hinweise**. | ⚠ dokumentiert |

## 4. Ausdrückliche Grenzen

* UScan erkennt nur, was die eingesetzten Engines und Signaturen kennen. ClamAV ist bei aktueller Windows-Malware schwächer als kommerzielle Engines; deshalb Defender als zweite Meinung.
* Ohne Kernel-Treiber gibt es **keine** Blockierung beim Dateizugriff. Beobachtete Ereignisse werden nachträglich geprüft.
* Ein „Unbekannt“ bei Reputation ist kein Malware-Befund.
* Eine Anwendung im Benutzermodus kann sich gegen einen Angreifer mit Administrator- oder Kernelrechten nicht zuverlässig schützen.
