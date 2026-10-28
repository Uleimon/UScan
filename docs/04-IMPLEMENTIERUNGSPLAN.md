# 04 – Implementierungsplan und Abnahmekriterien

Grundsatz: Eine Phase gilt erst als abgeschlossen, wenn **alle** Kriterien durch automatisierte Tests oder dokumentierte manuelle Prüfungen belegt sind. Windows-spezifische Kriterien können nur auf Windows abgenommen werden.

## Phase 1 – Analyse und Architektur ✅

| Kriterium | Nachweis |
|---|---|
| Supportstatus Windows/.NET/ClamAV mit Quellen dokumentiert | `01-ANALYSE-UND-PLATTFORM.md` |
| Module, Schnittstellen, Datenflüsse, Sicherheitsgrenzen festgelegt | `02-ARCHITEKTUR.md` |
| Bedrohungsmodell | `03-BEDROHUNGSMODELL.md` |
| Abnahmekriterien je Phase | dieses Dokument |

## Phase 2 – Funktionsfähiger Kern ✅

| # | Kriterium | Status |
|---|---|---|
| 2.1 | Projekt baut ohne Warnungen (`TreatWarningsAsErrors`, Analyzer „latest-recommended“) | ✅ Linux und Windows-CI |
| 2.2 | Echte Engine angebunden (`clamd`, INSTREAM) | ✅ |
| 2.3 | EICAR wird als Datei, im ZIP und dreifach verschachtelt erkannt | ✅ |
| 2.4 | Grenzwertüberschreitungen (Rekursion, Anzahl, Größe, Kompressionsverhältnis) → „Unvollständig“, nie „sauber“ | ✅ |
| 2.5 | Defekte Archive werden kontrolliert behandelt | ✅ |
| 2.6 | Symlinks/Reparse-Points werden nicht verfolgt | ✅ (Linux-Symlinks; auf Windows über dasselbe Attribut `ReparsePoint`, Junctions nicht separat getestet) |
| 2.7 | Zugriffsfehler je Datei/Verzeichnis werden protokolliert, Scan läuft weiter | ✅ (simuliert; echte ACLs nicht separat getestet) |
| 2.8 | Abbruch: Bericht `Cancelled`, nicht bearbeitete Dateien gezählt | ✅ |
| 2.9 | Engine-Ausfall während des Scans → `Aborted` | ✅ |
| 2.10 | Fortschritt nur aus erledigter Arbeit | ✅ |
| 2.11 | Strukturierter JSON-Bericht | ✅ (CLI `--json`) |
| 2.12 | Windows-Build + Tests in CI (`windows-latest`) mit ClamAV für Windows | ✅ |
| 2.13 | Dauerhaftes Ereignisprotokoll (rotierende JSON-Lines-Datei) | ✅ |

## Phase 3 – Sicherheitsfunktionen ✅ (mit dokumentierten Abweichungen)

| # | Kriterium | Status |
|---|---|---|
| 3.1 | Quarantäne: Verschieben, Integritätsfehler erkennen, Wiederherstellung mit Rescan, Symlink im Zielpfad abgelehnt, Ziel existiert, kein Datenverlust bei Abbruch | ✅ |
| 3.2 | Schutzliste für Systemdateien nur mit Admin-Bestätigung | ✅ |
| 3.3 | Updatestatus (Signaturalter), freshclam-Fehlercodes | ✅ |
| 3.4 | Inventar Run/RunOnce (HKLM/HKCU, WOW6432Node), Startup, Dienste, Aufgaben mit Authenticode, Herausgeber, SHA-256 | ✅ |
| 3.5 | PE-Heuristik mit Begründung, Fehlalarmtest gegen `System32\*.exe` (Ziel 0 Warnungen) | ✅ – Ergebnis in 06 |
| 3.6 | Defender als zweite Engine, Verhalten ohne Defender | ✅ |
| 3.7 | Hash-Reputation nur mit Opt-in | ⛔ nicht umgesetzt (kein Netzwerkzugriff vorhanden) |
| 3.8 | Dateiwächter, bezeichnet als „Nachscan, kein Blockieren“ | ✅ |
| – | Abweichung: kein LocalSystem-Dienst/IPC; alles läuft mit Benutzerrechten | siehe 10 |

## Phase 4 – Oberfläche (WPF) ✅ (teilweise)

| # | Kriterium | Status |
|---|---|---|
| 4.1 | Anzeige nur aus ViewModels mit Backend-Daten | ✅ |
| 4.2 | Sieben Zustände; „Geschützt“ ohne vollständige Voraussetzungen unerreichbar | ✅ Logik vollständig getestet, ViewModel-Tests für „rot“/„nicht grün“ |
| 4.3 | Hell/Dunkel ✅; Kontrast ≥ 4,5:1, Tastatur, Screenreader | 🟠 nicht systematisch geprüft |
| 4.4 | Fortschritt „Gesamtzahl unbekannt“ bis Aufzählung fertig | ✅ |

## Phase 5 – Verifikation ✅ (teilweise)

| # | Kriterium | Status |
|---|---|---|
| 5.1 | Build und alle Tests auf Windows | ✅ `windows-latest` · ⛔ Windows 10 22H2 / Windows 11 Client nicht automatisiert |
| 5.2 | Messung Erkennung/Fehlalarm/Durchsatz/RAM | 🟠 Fehlalarm gegen System32 und Durchsatz mit Test-Datenbank; keine Messung mit offizieller Datenbank |
| 5.3 | Abhängigkeits- und Lizenzprüfung | ✅ |
| 5.4 | Liste bekannter Einschränkungen | ✅ [10](10-BEKANNTE-PROBLEME-UND-ROADMAP.md) |
