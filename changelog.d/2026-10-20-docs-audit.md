### Docs — README/godoc ↔ код ↔ CA аудит (зөвхөн баримт)

**Юу.** README-ийн жишээ, хязгаар, алдааны код, godoc-ийг v0.12.0-ийн код, CA (`origin/main`), амьд `/.well-known/eid`,
`/mobile/app-config`-той тулгаж зөрүүг засав. Кодын зан өөрчлөгдөөгүй.

- `go get …@v0.4.0` → `@v0.12.0` (v0.4.0-д Share/ValidatePDF/PreviewCertificate байхгүй тул жишээ хөрвөхгүй байв).
- Share квот цагт 300 / өдөрт 3000 (өмнө 30/200); `ShareInfo.Enabled` туг биш — 503 `MAIL_UNAVAILABLE`/`VALIDATOR_UNAVAILABLE`.
- §4 алхам 1: `State != COMPLETE` → `*ValidationError`, `EndResult != OK` → `*SessionFailedError`.
- §7.1 `Page 0` = eID verify хуудас БИШ сүүлийн хуудас (v0.12.0, PLACEMENT_SPEC §1a); golden tag `pades-golden-v6` (v4 tag байхгүй).
- `Complete`-ийн давхарлалтын алдаа `STATE_INVALID`; ValidatePDF жишээнд `CodeRequestInvalid`; `RPName` ≤ 120 **байт**.
- Товчны CDN `@0.26.0` (0.15.4-д 429/503 Retry-After тоолуур байхгүй); status `PENDING`-ийн `vc`/`expiresIn`;
  аппын доод хувилбар iOS ≥ 2.2.8 / Android ≥ 91 (10-20); §3.7/§3.8 дараалал; English хэсгийн хамаарал.
- §3.2 / §3.7 жишээний `:=` давхар зарлалт засав (токены жишээ: оролт → preview → issue → result дараалал).
- godoc: `ShareInfo.Enabled`, share.go толгой, `Client` (Share/ShareInfo нь method), `ValidateCertificateChoice`
  (`SkipKeyUsageCheck`), `NationalRootCAPEM` (завсрын CA суусан), `Credentials.RPName`, `pades` package жишээ (`ValidatePDF`).

**Хэрхэн шалгасан.** README-ийн ```go блок бүрийг typed stub-тай боож `go build -gcflags=-e` (v0.12.0 replace) — үлдсэн нь
§3.4-ийн өмнөх хэсгээс `signer`/`dtbs` авдаг fragment л; `gofmt -l`, `go vet ./...`, `go test ./...`.

**Үлдсэн (код — энэ PR-д биш).** `WaitForResult` `DefaultMaxWait` 150 с < CA sign TTL 600 с; `CodeTokenIssuancePending`
тогтмол алга. CHANGELOG.md-ийн v0.11.0 «`signature.go` (`Visible.Avoid`)» (→ `appearance.go`) нэгтгэлийн үед засна.
