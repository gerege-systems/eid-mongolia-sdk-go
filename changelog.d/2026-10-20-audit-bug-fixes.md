### Fixed — SDK аудитын кодын алдаанууд (TS / .NET / Swift / Kotlin-той нийцүүлэв)

**Юу ба яагаад.**
- `Session.WaitForResult` 150 с-т таслахаа болив (CA auth 300 с, sign 600 с — иргэн 150 с-ээс хойш баталбал RUNNING
  буцаж validator унадаг байв). `MaxWait` өгөөгүй бол: `WaitOptions.ExpiresAt` (шинэ; start хариуны `ExpiresAt`) +
  `WaitGrace` (15 с) → discovery `sessionTtl` (max(auth, sign)) + 15 с → `DefaultMaxWait` (150 → **600 с**). `MaxWait`
  өгвөл түүнийг л дагана; long-poll хэвээр. Хугацаа өнгөрсөн `ExpiresAt`-д ч нэг poll хийнэ (CA-ийн TIMEOUT-ийг авна).
- Токены кодын тогтмолууд: `CodeTokenIssuancePending`, `CodeKYCIncomplete`, `CodeNoActiveDevice`, `CodeCSRKeyReused`,
  `CodeCSRInvalid`, `CodeCSRKeyUnsupported`, `CodeCSRSignatureInvalid`, `CodeCSRKeysIdentical`, `CodeIssuanceFailed`,
  `CodeResultExpired`, session-ий `CodeCSRDigestMismatch` / `CodeSignerCertChanged` / `CodeIssuanceError` /
  `CodeRegistryFailed`, токеноор нэвтрэлтийн `CodeRPRequired` / `CodeChallengeExpired` / `CodeChallengeUsed` /
  `CodeCertInvalid` / `CodeCertNotActive`; бүгдийг `TokenErrorCodes`-д (CA `tokencert.go`, `token_auth.go`).
- `pades.Complete`: RSASSA-PSS гарын үсэг → `SIGNATURE_INVALID` (өмнө `REQUEST_INVALID`; бусад 4 SDK, CA-ийн бүртгэлийн
  кодтой ижил). Мессеж («PKCS#1 v1.5 шаардлагатай») хэвээр.
- `pades.Registration`: `Medium` "" бол `SessionID`-аас (phone ⇔ sessionID — CA-ийн дүрэм; өмнө хоосноор илгээгдэж
  CA 400 буцаадаг байв); phone + SessionID "" / token + SessionID / үл мэдэгдэх medium → `REQUEST_INVALID`.
- `pades.Completed.ClaimedRole` (шинэ); `Registration` нь claimedRole-той гарын үсэгт `OnBehalfOf` хоосон бол
  `REQUEST_INVALID` (өмнө CA дараа нь татгалздаг байв).
- `TokenService` godoc: олголтод зөвхөн `TOKEN_ISSUE` эрх («TOKEN_ISSUE + SIGN» биш).

**Хаана.** `session.go`, `auth.go` (`fetchSessionTTL`), `token.go`, `pades/complete.go`, `pades/register.go`, README.

**Хэрхэн шалгасан.** `TestWaitDeadline` (discovery / ExpiresAt / өнгөрсөн ExpiresAt / MaxWait / хуучин CA / 503),
`TestSession_PollAndWait`, `TestRegistrationAndPSS`, `TestRegistrationMediumAndRole`; `gofmt -l`, `go vet ./...`,
`go test ./...`, `GOOS=linux go build ./...`.
