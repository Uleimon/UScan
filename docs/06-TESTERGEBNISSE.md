# 06 – Teststrategie und tatsächliche Testergebnisse

## Teststrategie

| Ebene | Werkzeug | Inhalt |
|---|---|---|
| Unit | xUnit v3 | Antwortparser, SHA-256, ZIP-Grenzprüfung, Statuslogik, Scan-Orchestrierung mit deterministischer Fake-Engine |
| Protokoll | xUnit + Fake-`clamd` (TCP) | Framing von INSTREAM, vorzeitiges Schließen, Timeout, unerreichbarer Dienst, übergroße Antworten, Loopback-Erzwingung |
| Integration | xUnit + echter `clamd` | Fixture startet einen privaten `clamd` auf zufälligem Loopback-Port mit Test-Signatur (EICAR per MD5). Ohne installiertes ClamAV werden diese Tests als **übersprungen** gemeldet, nicht als bestanden. |
| Laufzeit | CLI gegen echten `clamd` | Ende-zu-Ende inkl. Exit-Codes, JSON-Bericht, Engine-Ausfall |

Testdaten: ausschließlich harmlos. EICAR wird zur Laufzeit zusammengesetzt; ZIP-Bomben bestehen aus Nullbytes. **Keine echte Malware.**

## Ergebnisse vom 28.10.2026

Umgebung: Ubuntu 24.04 (Container), 4 vCPU, .NET SDK 10.0.113, ClamAV 1.5.4, Test-Signaturdatenbank mit einer Signatur.

```
dotnet test   →  Passed: 70, Failed: 0, Skipped: 0   (3 Läufe hintereinander, identisch)
USCAN_CLAMD=/nonexistent dotnet test  →  Passed: 60, Skipped: 10  (Skip-Pfad geprüft)
dotnet list package --vulnerable --include-transitive  →  keine bekannten Schwachstellen
```

| Testklasse | Tests |
|---|---|
| ClamdResponseParserTests | 19 |
| ClamdProtocolTests | 9 |
| HashingReadStreamTests | 4 |
| ZipLimitInspectorTests | 8 |
| StatusEvaluatorTests | 9 |
| ScanRunnerTests | 11 |
| ClamdIntegrationTests (echter clamd) | 10 |

### Wichtige Einzelbefunde

* **Gefundener Testdatenfehler:** Ein Versions-Testdatum enthielt einen falschen Wochentag; der Parser lehnte es korrekt ab (Test korrigiert).
* **ClamAV-Verhalten (Regressionstest `Oversized_zip_member_is_incomplete_not_clean`):** 30-MB-ZIP-Eintrag bei `MaxFileSize 10M` → `clamd` antwortet `OK`. UScan meldet „Unvollständig geprüft“.
* `MaxRecursion` und `MaxFiles` werden von ClamAV korrekt als `Heuristics.Limits.Exceeded.*` gemeldet → „Unvollständig“.

### Laufzeitprüfung CLI

Ordner mit EICAR, EICAR-ZIP, ZIP-Bombe, verschachteltem ZIP, defektem ZIP, normaler Textdatei und Symlink:

```
UNVOLLSTÄNDIG  bomb.zip     Entry 'zeros.bin' declares 31457280 bytes; engine limit per entry is 10485760 …
UNVOLLSTÄNDIG  corrupt.zip  ZIP structure could not be read …
INFIZIERT      e.zip        UScan.Test.EICAR.UNOFFICIAL
INFIZIERT      eicar.txt    UScan.Test.EICAR.UNOFFICIAL  sha256=275a021b…fd0f
UNVOLLSTÄNDIG  nested.zip   Heuristics.Limits.Exceeded.MaxRecursion
ÜBERSPRUNGEN   sub/link     übersprungen (ReparsePointOrSymlink)
Dateien: 7 gefunden, 1 ohne Befund, 2 infiziert, 0 verdächtig, 3 unvollständig geprüft, 1 übersprungen, 0 Fehler
Exit-Code 1
```

Engine gestoppt → `status` Exit-Code 3 „nicht erreichbar“, `scan` „wegen Engine-Fehler abgebrochen“, keine Datei als sauber gemeldet. Entfernter Host `8.8.8.8` → abgelehnt (Exit 64).

### Leistung (nur eingeschränkt aussagekräftig)

`/usr/lib/python3.12` (54 MB, 1 215 Dateien), Release-Build, `--parallel 4`:
**2,3 s**, Spitzen-RAM des UScan-Prozesses **≈ 158 MB** (RSS), `clamd` ≈ 23 MB RSS.

Diese Zahl ist **nicht repräsentativ**: Mit der offiziellen Datenbank (Millionen Signaturen) braucht `clamd` typischerweise über 1 GB RAM und scannt langsamer. Echte Leistungsmessungen gehören auf Windows mit offizieller Datenbank (Phase 5).

### Nicht gemessen

Erkennungsrate und Fehlalarmrate mit offiziellen Signaturen (nicht verfügbar in dieser Umgebung), Verhalten unter Windows, CPU-Auslastung.

## Tests selbst ausführen

```bash
dotnet test                                  # alle Tests; Integration nur mit installiertem clamd
USCAN_CLAMD="C:\Program Files\ClamAV\clamd.exe" dotnet test   # Windows: Pfad explizit setzen
```
