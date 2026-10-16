- **Нэмэгдсэн — `Client.Share`: гарын үсэгтэй файлыг имэйлээр (CA `POST /share`).**
  - Юу: `Share(ctx, ShareRequest{File, Filename, To, Subject, Message, Lang}) (*ShareResult, error)` — multipart
    (`ShareResult{Sent, SHA256, Signatures, DocID, Raw}`); `ShareInfo(ctx)` — discovery-ийн `share` блок (`Enabled`,
    формат, хязгаар, `Quota`). Алдаа `*ShareError` (`APIError` embed + `Unwrap`; `Reason` (422), `Sent`/`Failed`/
    `Recipients` (502 MAIL_FAILED)); кодууд `CodeFileEmpty` … `CodeValidatorBusy`, `ShareErrorCodes`,
    `ShareReason*`, `ShareRecipient*`, `DefaultShareTimeout` (150 с).
  - Нэмэгдсэн: `PersonCertificate.IssuedAt`, `RevokedAt`, `RevocationReason` (RFC 5280 нэр).
  - Яагаад: CA main 0329ef95 (!371) — `rp./share` (туг `EID_SHARE_ENABLED`, одоогоор унтраалттай) ба `/certificates`-ийн
    шинэ талбарууд; портал Go SDK-аар дуудна. TS SDK 0.18.0-тэй ижил.
  - Хаана: `share.go`, `routes.go` (`routeShare`), `client.go`, `person.go`, `share_test.go`, `contract_test.go`
    (`TestContractShare`), README §3.6/§3.8/§5.
  - Шалгасан: `gofmt`, `go vet`, `go test -race ./...`, `GOOS=linux go build`, `go test -tags contract -run Contract`
    live discovery-тэй (share зам, multipart талбар, `share` блок).
