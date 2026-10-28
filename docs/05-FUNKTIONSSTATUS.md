# 05 – Funktionsstatus (implementiert vs. geplant)

Stand 28.10.2026. „Getestet“ heißt: automatisierter Test vorhanden und in diesem Stand tatsächlich ausgeführt (Linux, ClamAV 1.5.4, Test-Signaturdatenbank).

| Bereich | Funktion | Status |
|---|---|---|
| A Signaturen | Scan über ClamAV (`clamd`, INSTREAM) | ✅ implementiert, getestet |
| | Anzeige Engine-/Datenbankversion und -alter | ✅ (CLI `status`) |
| | Signatur-Update (`freshclam`) steuern und überwachen | ❌ nicht implementiert (nur Altersprüfung) |
| | Validierung beschädigter Datenbanken | ❌ (übernimmt `clamd`/`freshclam`; eigene Tests fehlen) |
| B Heuristik | Eigene PE-/Skript-Heuristik | ❌ nicht implementiert. ClamAV-eigene `Heuristics.*` werden als „Verdächtig“ (nicht „Infiziert“) gemeldet. |
| C Verhalten | Autostart-/Prozess-/Massenänderungs-Überwachung | ❌ nicht implementiert |
| D Archive | ZIP und weitere Formate über ClamAV | ✅ ZIP getestet; andere Formate von ClamAV unterstützt, aber **nicht von uns getestet** |
| | Limits für Rekursion, Anzahl, Größe, Kompressionsverhältnis | ✅ getestet |
| | Defekte Archive | ✅ getestet (ZIP) |
| | Nicht unterstützte Formate ausweisen | ❌ (ClamAV meldet nicht, ob ein Format verstanden wurde) |
| E Hash/Reputation | SHA-256 jeder gescannten Datei | ✅ getestet |
| | Reputationsdienst (Opt-in) | ❌ nicht implementiert |
| F Rootkit/Manipulation | – | ❌ nicht implementiert |
| 3 Echtzeit | Dateiwächter, Ransomware-Schutz, Benachrichtigungen | ❌ nicht implementiert. Status zeigt deshalb „Schutz eingeschränkt“. |
| 4 Quarantäne | – | ❌ nicht implementiert (Entwurf in Architektur §5) |
| 5 System-/Startup-Analyse | – | ❌ nicht implementiert |
| 6 Scanmodi | Benutzerdefinierter Scan (Ordner/Dateien) | ✅ (CLI) |
| | Archivscan | ✅ (Teil jedes Scans) |
| | Schnellscan, Vollscan, Autostart-Scan | ❌ (benötigt Windows-Pfadauswahl/Inventar) |
| | Zweiter Prüfmodus (Defender) | ❌ |
| | Offline-Vorbereitung | ❌ – wird **nie** als verfügbar angezeigt, solange keine getestete Lösung integriert ist |
| | Fortschritt, übersprungene Dateien, Fehler, Dauer, Abbruch | ✅ getestet |
| 7 Oberfläche | WPF-App | ❌ nicht implementiert (CLI vorhanden) |
| | Statuslogik mit 7 Zuständen | ✅ Logik getestet, noch ohne GUI |
| 8 Updates | Programm-Updates | ❌ |
| 9 Datenschutz | Keine Netzwerkverbindung außer zu lokalem `clamd`; entfernte Hosts nur mit Opt-in | ✅ getestet |
| | Telemetrie | keine vorhanden |
