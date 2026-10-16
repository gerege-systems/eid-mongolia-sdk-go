# Токены сунгалтын scope түгжээ — TOKEN_SCOPE_CHANGE (CA !373)

- **Юу:** `CodeTokenScopeChange` (`TOKEN_SCOPE_CHANGE`), `CodeTokenInUse` (`TOKEN_IN_USE`) тогтмол;
  `c.Token.CertificateInfo(ctx)` → discovery-ийн `tokenCertificate` блок (`TokenCertInfo`, `ScopeLockedOnRenewal`);
  `IssueCertificate` / `CertificateResult`-ийн doc, `TokenCertSessionBlock.ErrorCode`-ийн жагсаалт, README §3.7-д дүрэм.
- **Яагаад:** CA main 0d1f3f63 (!373): ижил `tokenSerial` дээр ACTIVE бүртгэлтэй үед сунгалт scope-ийг (хувийн ↔
  байгууллага, өөр `onBehalfOf`) солих гэвэл `POST /token/certificate`, `GET /token/certificate/{id}` 409
  `TOKEN_SCOPE_CHANGE`, session-ий `tokenCertificate.errorCode` мөн; override үгүй — иргэн eID апп-аас токеноо
  цуцлаад шинээр олгуулна. Discovery: `tokenCertificate.scopeLockedOnRenewal: true`.
- **Хаана:** `token.go`, `types.go`, `README.md`, `portal_gaps_test.go`, `contract_test.go`.
- **Шалгасан:** `gofmt`, `go vet`, `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build ./...`,
  `go test -tags contract -run Contract` (live discovery-д `scopeLockedOnRenewal: true`).
