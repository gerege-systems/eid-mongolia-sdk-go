### Added — `Token.PreviewCertificate` (dryRun), `TokenCertInfo.DryRun`

- **Юу:** `c.Token.PreviewCertificate(ctx, in)` — `POST /token/certificate` ижил бие + `"dryRun": true` →
  `*TokenCertPreview{Supersedes}`; алдаа `IssueCertificate`-тэй ижил (`*APIError`, `TokenLimitOf` …); хариунд
  `dryRun: true` алга бол `*ValidationError`. Оролтын шалгалт/бие угсралт нэг `certRequest`-д. Discovery `TokenCertInfo.DryRun`.
- **Яагаад:** `Supersedes` бодит эхлэлийн хариунд ирэх үед PIN2 push явсан байдаг; RP push-ээс өмнө иргэнд анхааруулах
  хэрэгтэй (CA MR feat/token-cert-dryrun).
- **Хаана:** `token.go`, README §3.7, `portal_gaps_test.go` (`TestTokenCertificatePreview`), `contract_test.go`
  (`dryRun` CA deploy болтол лог, дараа нь шаардлага).
- **Шалгасан:** `gofmt`, `go vet`, `go test ./...`, contract тест live discovery-д.
