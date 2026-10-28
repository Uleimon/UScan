# 04 – Implementierungsplan und Abnahmekriterien

Grundsatz: Eine Phase gilt erst als abgeschlossen, wenn **alle** Kriterien durch automatisierte Tests oder dokumentierte manuelle Prüfungen belegt sind. Windows-spezifische Kriterien können nur auf Windows abgenommen werden.

## Phase 1 – Analyse und Architektur ✅ (dieser Stand)

| Kriterium | Nachweis |
|---|---|
| Supportstatus Windows/.NET/ClamAV mit Quellen dokumentiert | `01-ANALYSE-UND-PLATTFORM.md` |
| Module, Schnittstellen, Datenflüsse, Sicherheitsgrenzen festgelegt | `02-ARCHITEKTUR.md` |
| Bedrohungsmodell | `03-BEDROHUNGSMODELL.md` |
| Abnahmekriterien je Phase | dieses Dokument |

## Phase 2 – Funktionsfähiger Kern (begonnen, plattformneutraler Teil ✅)

| # | Kriterium | Status |
|---|---|---|
| 2.1 | Projekt baut ohne Warnungen (`TreatWarningsAsErrors`, Analyzer „latest-recommended“) | ✅ Linux · ⏳ Windows-CI |
| 2.2 | Echte Engine angebunden (`clamd`, INSTREAM) | ✅ |
| 2.3 | EICAR wird als Datei, im ZIP und dreifach verschachtelt erkannt | ✅ |
| 2.4 | Grenzwertüberschreitungen (Rekursion, Anzahl, Größe, Kompressionsverhältnis) → „Unvollständig“, nie „sauber“ | ✅ |
| 2.5 | Defekte Archive werden kontrolliert behandelt | ✅ |
| 2.6 | Symlinks/Reparse-Points werden nicht verfolgt | ✅ (Linux-Symlinks; Junctions auf Windows ⏳) |
| 2.7 | Zugriffsfehler je Datei/Verzeichnis werden protokolliert, Scan läuft weiter | ✅ (simuliert) · ⏳ echte ACLs auf Windows |
| 2.8 | Abbruch: Bericht `Cancelled`, nicht bearbeitete Dateien gezählt | ✅ |
| 2.9 | Engine-Ausfall während des Scans → `Aborted` | ✅ |
| 2.10 | Fortschritt nur aus erledigter Arbeit | ✅ |
| 2.11 | Strukturierter JSON-Bericht | ✅ (CLI `--json`) |
| 2.12 | Windows-Build + Tests in CI (`windows-latest`) mit ClamAV für Windows | ⏳ benötigt Repository |
| 2.13 | Dauerhaftes Ereignisprotokoll (rotierende JSON-Lines-Datei) | ⏳ |

## Phase 3 – Sicherheitsfunktionen

| # | Kriterium |
|---|---|
| 3.1 | Quarantäne nach Abschnitt 5 der Architektur; Tests: Verschieben, Integritätsfehler erkennen, Wiederherstellung mit Rescan, Symlink im Zielpfad wird abgelehnt, Zielpfad existiert, Abbruch mitten in der Operation hinterlässt keinen Datenverlust |
| 3.2 | Schutzliste für Systemdateien, Test: Quarantäne von `%SystemRoot%\System32\*.dll` ohne Admin-Bestätigung wird abgelehnt |
| 3.3 | Updatestatus: Signaturalter, Engine-EOL; Tests mit beschädigter/fehlender Datenbank |
| 3.4 | Systeminventar: Run/RunOnce (HKLM/HKCU, WOW6432Node), Startup-Ordner, Dienste, geplante Aufgaben – jeweils mit Authenticode-Status (`WinVerifyTrust`), Herausgeber, SHA-256 |
| 3.5 | Heuristik v1 (PE): gewichtete Merkmale (z. B. unsigniert + in Benutzer-Temp + Autostart + hohe Sektionsentropie), Schwelle, Begründungstext je Merkmal; Fehlalarmtest gegen alle signierten Dateien in `System32` (Ziel: 0 Warnungen) |
| 3.6 | Defender-Adapter als zweite Engine (`MpCmdRun -Scan -ScanType 3 -File … -DisableRemediation`); Verhalten bei fehlendem/deaktiviertem Defender getestet |
| 3.7 | Hash-Reputation nur mit Opt-in; Test, dass ohne Zustimmung keine Netzwerkverbindung entsteht |
| 3.8 | Dateiwächter (Nachscan neuer Dateien) – in der Oberfläche als „Überwachung (kein Echtzeit-Blockieren)“ bezeichnet |

## Phase 4 – Oberfläche (WPF)

| # | Kriterium |
|---|---|
| 4.1 | Jede Anzeige stammt aus einem ViewModel, das nur Backend-Daten enthält; keine Platzhalter-Erfolgsmeldungen |
| 4.2 | Alle sieben Statuszustände sind erreichbar und per UI-Test geprüft; „Geschützt“ ist ohne vollständige Voraussetzungen nicht erreichbar |
| 4.3 | Dunkles und helles Design, Kontrast ≥ 4,5:1 (WCAG AA), vollständig per Tastatur bedienbar, Screenreader-Namen gesetzt |
| 4.4 | Fortschritt zeigt „Gesamtzahl unbekannt“, bis die Aufzählung abgeschlossen ist |

## Phase 5 – Verifikation

| # | Kriterium |
|---|---|
| 5.1 | Sauberer Build und alle Tests auf Windows 11 (aktuelle Version) und Windows 10 22H2 (ESU) |
| 5.2 | Messung auf definiertem Datensatz: Erkennungsrate (EICAR-Varianten + öffentlich verfügbare harmlose Testdateien), Fehlalarmrate (saubere Windows-Installation + gängige Software), Durchsatz, RAM, CPU – jeweils mit Versionen und Testbedingungen |
| 5.3 | Abhängigkeits- und Lizenzprüfung (`dotnet list package --vulnerable`, Lizenzliste) |
| 5.4 | Liste bekannter Einschränkungen aktuell |

## Nächste konkrete Schritte

1. Repository anlegen (durch dich auf GitHub), Code hochladen, Windows-CI einrichten (Build + Tests mit ClamAV für Windows).
2. Ereignisprotokoll und persistente Scanberichte.
3. `UScan.Windows`: Authenticode-Prüfung und Autostart-Inventar – zuerst, weil sie ohne Privilegien und ohne Systemänderungen auskommen.
4. Quarantäne.
