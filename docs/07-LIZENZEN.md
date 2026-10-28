# 07 – Lizenzübersicht der Abhängigkeiten

Keine Rechtsberatung. Vor einer Veröffentlichung juristisch prüfen lassen.

| Komponente | Version | Lizenz | Verwendung |
|---|---|---|---|
| .NET Runtime / SDK | 10.0 | MIT | Laufzeit, Build |
| ClamAV (`clamd`, `freshclam`) | 1.5.4 (getestet) | GPL-2.0 (einzelne Bestandteile unter weiteren freien Lizenzen) | **separater Prozess**, Kommunikation über das dokumentierte Socket-Protokoll; UScan linkt nicht gegen libclamav |
| Microsoft Defender (`MpCmdRun.exe`) | Bestandteil von Windows | Windows-Lizenz | nur aufgerufen, nicht ausgeliefert |
| ClamAV-Signaturdatenbanken | – | Nutzungsbedingungen von Cisco Talos / ClamAV | Download durch `freshclam`; Bedingungen und Rate-Limits vor kommerzieller Verteilung prüfen |
| System.ServiceProcess.ServiceController | 10.0.0 | MIT | Dienste lesen (UScan.Windows) |
| System.Management | 10.0.0 | MIT | WMI: Defender-Status, Windows-Sicherheitscenter (UScan.Windows) |
| WPF (Microsoft.WindowsDesktop.App) | 10.0 | MIT | Oberfläche |
| xunit.v3 | 3.0.1 | Apache-2.0 | nur Tests |
| xunit.runner.visualstudio | 3.1.4 | Apache-2.0 | nur Tests |
| Microsoft.NET.Test.Sdk | 17.14.1 | MIT | nur Tests |
| Microsoft.Extensions.TimeProvider.Testing | 10.11.0 | MIT | nur Tests |

**Hinweise zu ClamAV:** Wer ClamAV-Binärdateien zusammen mit UScan ausliefert, muss die GPL-2.0-Pflichten erfüllen (Lizenztext beilegen, Quellcode der ausgelieferten ClamAV-Version anbieten). Alternativ installiert der Nutzer ClamAV selbst über das offizielle Installationspaket.

**Eigener Code:** Lizenz noch festzulegen (Vorschlag: MIT oder Apache-2.0).
