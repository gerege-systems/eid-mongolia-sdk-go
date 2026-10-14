- **v0.2.2 — CA !357 (fd3acf14, прод 2026-10-14)-тэй нийцүүлэв.**
  - `ExpiresAt`: session start хариуны CA-ийн `expiresAt` (RFC 3339) — sign / certificate-choice (push, device-link,
    linked) ба auth (push, device-link). Талбаргүй / задрахгүй (хуучин CA) үед sign/cert-choice-д `SessionExpiry`
    тооцоолол, auth-д тэг.
  - `errors.Is` sentinel: `ErrNoSigningCertificate` (409 `NO_SIGNING_CERTIFICATE`), `ErrCertChoiceInvalid` (409
    `CERT_CHOICE_INVALID`), `ErrRequestInvalid` (400 `REQUEST_INVALID`) — `*APIError.Is` нь `Code`-оор тулгана;
    `Code*` тогтмолууд. `errors.As(&*APIError)` хэвээр.
- Хаана: `auth.go`, `sign.go`, `certchoice.go`, `errors.go`, `types.go`, `README.md`.
- Шалгасан: `session_start_test.go` (CA expiresAt / fallback / typed алдаа); `gofmt`, `go vet`, `go test ./...`,
  `GOOS=linux go build`.
