# 09 – Schlüsselverwaltung für Programm-Updates

UScan installiert Programm-Updates nur, wenn das Update-Manifest mit einem Schlüssel signiert ist, dessen **öffentlicher** Teil neben dem Programm liegt. Im Repository liegt **kein** Schlüssel – weder öffentlich noch privat. Wer UScan verteilt, erzeugt seinen eigenen Schlüssel.

## Verfahren

* Algorithmus: ECDSA mit Kurve P-256 und SHA-256. Andere Kurven werden abgelehnt.
* Signiert werden die exakten Bytes der Manifest-Datei (JSON); die Signatur liegt daneben (`.sig`). Akzeptiert werden das rohe r‖s-Format (.NET-Standard) und DER (OpenSSL).
* Das Manifest nennt die Schlüssel-ID (`keyId`). Der Client sucht `keys/<keyId>.pem`. Mehrere Schlüssel gleichzeitig sind erlaubt – das ermöglicht Rotation.

## Schlüssel erzeugen (auf einem vertrauenswürdigen, möglichst nicht vernetzten Rechner)

```powershell
uscan release keygen D:\release-keys
# → release-private.pem  (GEHEIM)
# → release-public.pem   (wird ausgeliefert)
```

oder mit OpenSSL:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out release-private.pem
openssl ec -in release-private.pem -pubout -out release-public.pem
```

## Release signieren

1. Paket bauen: `dotnet publish … -o out` und `out` als ZIP packen.
2. SHA-256 und Größe ermitteln: `Get-FileHash uscan-0.6.0.zip -Algorithm SHA256`, `(Get-Item uscan-0.6.0.zip).Length`.
3. Manifest schreiben (Feldnamen exakt so, unbekannte Felder werden abgelehnt):
   ```json
   {
     "product": "UScan",
     "channel": "stable",
     "version": "0.6.0",
     "publishedAt": "2026-11-01T10:00:00+00:00",
     "expiresAt": "2026-12-01T10:00:00+00:00",
     "keyId": "release-2026",
     "package": { "fileName": "uscan-0.6.0.zip", "sha256": "<64 Hex-Zeichen>", "size": 12345678 }
   }
   ```
4. Signieren: `uscan release sign uscan-0.6.0.json D:\release-keys\release-private.pem` (oder `openssl dgst -sha256 -sign release-private.pem -out uscan-0.6.0.json.sig uscan-0.6.0.json`).
5. Ausliefern: ZIP, Manifest, `.sig`. Der öffentliche Schlüssel wird einmalig als `keys\release-2026.pem` mit dem Programm verteilt.

## Regeln

* Der private Schlüssel kommt **nie** ins Repository, in CI-Logs oder auf Verteil-Server. Für CI-Signierung: geheime Variable bzw. besser ein Hardware-Token/HSM.
* Kurze Laufzeit der Manifeste (`expiresAt`, z. B. 30 Tage): ein Angreifer kann ein altes, gültiges Manifest nicht unbegrenzt ausspielen (Freeze-Angriff); Downgrades lehnt UScan unabhängig davon ab.
* **Rotation:** neuen Schlüssel erzeugen, öffentlichen Teil mit einem Update ausliefern (beide Schlüssel parallel), danach nur noch mit dem neuen signieren und den alten in einem weiteren Update entfernen.
* **Kompromittierung:** Ein gestohlener Schlüssel kann nur durch ein Update mit neuem Schlüsselsatz entwertet werden, das mit einem noch vertrauenswürdigen Schlüssel signiert ist. Deshalb empfiehlt sich ein zweiter, offline verwahrter Schlüssel, der nur für solche Notfälle genutzt wird. Eine zweistufige Root/Targets-Hierarchie wie bei „The Update Framework“ ist noch nicht umgesetzt (siehe Roadmap).
* Zusätzlich sollten die ausgelieferten `.exe`/`.dll` mit Authenticode signiert werden (Code-Signing-Zertifikat); das ist noch nicht eingerichtet.
