# 03 – Bedrohungsmodell und Sicherheitsgrenzen

Methode: STRIDE je Komponente aus `02-ARCHITEKTUR.md`. Spalte „Status“: ✅ umgesetzt und getestet, ⛔ nicht umgesetzt, ⚠ Restrisiko. Stand: Version 0.5.0.

## 1. Schützenswerte Güter

1. Dateien und Privatsphäre der Nutzer (Inhalte, Pfade, Hashes)
2. Integrität des Systems (keine Schäden durch Fehlalarme oder fehlerhafte Quarantäne)
3. Ehrlichkeit der Statusanzeige (ein falsches „Geschützt“ ist selbst ein Sicherheitsproblem)
4. Signaturdatenbank und Programmupdates
5. Quarantäne-Inhalte (enthalten Malware, dürfen nicht versehentlich ausgeführt oder wiederhergestellt werden)
6. Release-Signierschlüssel für Programm-Updates

## 2. Angreifer

* **A1 Schadhafte Datei** auf dem Datenträger (passiv, will Parser ausnutzen, Scan umgehen oder Ressourcen erschöpfen)
* **A2 Lokaler Prozess mit Benutzerrechten** (z. B. Malware, die bereits läuft)
* **A3 Netzwerkangreifer** (Update-Manipulation, Man-in-the-Middle)
* **A4 Lokaler Administrator / Kernel-Malware** – liegt **außerhalb** dessen, wovor eine Anwendung im Benutzermodus schützen kann

## 3. Bedrohungen und Gegenmaßnahmen

| # | Komponente | STRIDE | Bedrohung | Gegenmaßnahme | Status |
|---|---|---|---|---|---|
| T1 | Scan-Engine | E/D | Präparierte Datei nutzt Parserfehler in ClamAV aus | Parser läuft in separatem `clamd`-Prozess; Absturz/Verbindungsabbruch → Engine-Fehler, kein falsches „sauber“. Eigene Heuristik nutzt nur verwaltete Parser (`PEReader`, `ZipArchive`) mit Größenlimits und Regex-Timeouts | ✅ · ⚠ clamd-Dienstkonto liegt in der Verantwortung der ClamAV-Installation |
| T2 | Archive | D | ZIP-Bombe, tiefe Verschachtelung, Millionen Einträge | `clamd`-Limits (`MaxFileSize`, `MaxScanSize`, `MaxRecursion`, `MaxFiles`, `MaxScanTime`) + `AlertExceedsMax`; UScan meldet `Incomplete`; eigene Prüfung des Zentralverzeichnisses mit Kompressionsverhältnis | ✅ (Tests T-INT-4…7) |
| T3 | Archive | T (Reporting) | ClamAV kürzt zu große ZIP-Einträge still und meldet „OK“ | `ZipLimitInspector` stuft auf „Unvollständig“ herab | ✅ Regressionstest |
| T4 | Archive | T | Gefälschte Größenangaben im ZIP-Verzeichnis | Nur Berichtsschutz; Durchsetzung erfolgt durch ClamAV-Limits. | ⚠ dokumentiert |
| T5 | Scanner | T/I | Symlink/Junction leitet Scan in fremde Bereiche oder erzeugt Endlosschleifen | Reparse-Points werden nie verfolgt und als „übersprungen“ gemeldet; Tiefenlimit | ✅ |
| T6 | Scanner | D | Datei wird während des Scans vergrößert | Stream-Limit wird beim Senden erneut geprüft → `Skipped` | ✅ |
| T7 | Scanner | R | Abbruch/Fehler wird als „sauber“ dargestellt | eigene Verdicts `Error`, `Incomplete`, `Skipped`; `FilesNotProcessed`; unbekannte Engine-Antwort → `Error` | ✅ |
| T8 | clamd-TCP | S/I/E | Lokaler Prozess verbindet sich mit `clamd` und nutzt `SCAN <pfad>` mit dessen Rechten | UScan nutzt nur `INSTREAM`; nur Loopback; Beispielkonfiguration bindet an 127.0.0.1 | ✅ Client · ⚠ Härtung des clamd-Kontos nicht automatisiert |
| T9 | clamd-TCP | D | Lokaler Prozess blockiert `clamd` mit Anfragen | `MaxThreads`/`MaxQueue`; UScan-Timeouts → `Error` statt Hängen | ✅ Timeout · ⚠ DoS durch A2 möglich |
| T10 | Client | I | Dateiinhalte werden versehentlich an entfernten Host gesendet | Nicht-Loopback-Hosts nur nach explizitem Opt-in | ✅ |
| T11 | Status | S | Oberfläche zeigt „Geschützt“, obwohl Engine aus/veraltet | `StatusEvaluator`: „Geschützt“ nur, wenn **jede** Voraussetzung positiv bekannt ist; fehlendes Echtzeitmodul → „Schutz eingeschränkt“ | ✅ (vollständige Negativtests) |
| T12 | Updates | T/S | Manipulierte Signaturen oder Programmpakete | `freshclam` prüft Datenbanksignaturen, Fehlercode 54 wird als Ablehnung gemeldet; Programm-Manifest mit ECDSA P-256 (gepinnter öffentlicher Schlüssel), Paket-SHA-256 und Größe, Schutz gegen Pfad-Traversal/Links/Größenbomben beim Entpacken | ✅ |
| T13 | Updates | T | Downgrade-/Freeze-Angriff | Version muss größer als installiert sein, Ablaufdatum im signierten Manifest, Signaturalter → „Update erforderlich“ | ✅ |
| T14 | Rechte | E | Unprivilegierter Prozess bringt UScan dazu, fremde Dateien zu löschen | UScan läuft nur mit Benutzerrechten (kein Dienst, keine IPC); löscht nur nach eigener Erkennung, Hash-Gleichheit und Bestätigung; Schutzliste | ✅ (kein privilegierter Angriffspunkt vorhanden) |
| T15 | Quarantäne | T/E | Wiederherstellung über Symlink in Systemordner, Race zwischen Prüfung und Löschen | Reparse-Prüfung der Zielkette, kein Überschreiben, Temp + Umbenennen; vor dem Löschen Umbenennen im selben Ordner und erneutes Hashen | ✅ |
| T16 | Quarantäne | D (Integrität) | Fehlalarm verschiebt Systemdatei → System startet nicht | Schutzliste, Standardaktion nie „Löschen“, Bestätigung, verifizierte Wiederherstellung; Heuristik maximal „Verdächtig“ und nicht vorausgewählt | ✅ |
| T17 | Reputation | I | Hash-Abfrage verrät, welche Dateien jemand besitzt | Kein Reputationsdienst eingebaut → keine Abfragen | ⛔ (Funktion nicht vorhanden) |
| T18 | Protokolle | I | Logs enthalten Benutzerpfade | nur lokal im Benutzerprofil, Rotation (5 × 5 MB), keine Übertragung | ✅ |
| T19 | Selbstschutz | T | Malware beendet UScan oder ändert Quarantäne/Protokoll | Überwachung meldet sich über Heartbeat; fehlt er, zeigt der Status „Schutz eingeschränkt“. Malware mit Benutzerrechten kann UScan-Daten im Profil ändern; GCM erkennt manipulierte Quarantäne-Objekte. Echter Selbstschutz ist ohne Kernel-Komponente (PPL/ELAM) **nicht möglich**. | ⚠ |
| T21 | Überwachung | D/R | Änderungsbenachrichtigungen gehen verloren (Pufferüberlauf) oder Datei wird vor dem Scan ausgeführt | Verluste werden gezählt und als Warnung „manuell scannen“ gemeldet; Oberfläche und CLI sagen ausdrücklich „blockiert nicht“ | ✅ · ⚠ Ausführung vor Scan bleibt möglich |
| T22 | Heuristik | D | ReDoS durch präparierte Skripte | alle Regex mit 500-ms-Timeout, Größenlimit 2 MB | ✅ |
| T23 | Release-Schlüssel | S | Gestohlener Signierschlüssel | Schlüssel nie im Repository; Schlüssel-ID im Manifest, mehrere öffentliche Schlüssel möglich (Rotation); siehe 09 | ⚠ organisatorisch |
| T20 | Gesamt | – | Kernel-Rootkit verbirgt Dateien/Prozesse vor Benutzermodus-APIs | Nicht lösbar im Benutzermodus. Empfehlung: Microsoft Defender Offline-Scan. Inventar-Abgleich (z. B. Dienste via SCM vs. Registry) liefert nur **Hinweise**. | ⚠ dokumentiert |

## 4. Ausdrückliche Grenzen

* UScan erkennt nur, was die eingesetzten Engines und Signaturen kennen. ClamAV ist bei aktueller Windows-Malware schwächer als kommerzielle Engines; deshalb Defender als zweite Meinung.
* Ohne Kernel-Treiber gibt es **keine** Blockierung beim Dateizugriff. Beobachtete Ereignisse werden nachträglich geprüft.
* Ein „Unbekannt“ bei Reputation ist kein Malware-Befund.
* Eine Anwendung im Benutzermodus kann sich gegen einen Angreifer mit Administrator- oder Kernelrechten nicht zuverlässig schützen.
