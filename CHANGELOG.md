# Changelog

## Unreleased

- **Гэрээний шалгалт** (`go test -tags contract`, `.github/workflows/contract.yml` — PR / main / өдөр бүр): SDK-ийн
  RP-API зам бүр live `/.well-known/eid`-д, OIDC утгууд (issuer, ES256, S256, client_secret_basic, `Claims` талбарууд)
  `openid-configuration`-д таарахыг шалгана; SDK хамраагүй discovery замууд WARN. RP-API замууд `routes.go`-д нэг
  газар төвлөрсөн (зан төлөв өөрчлөгдөөгүй). Энгийн `go test` сүлжээгүй хэвээр.

## 0.1.1 — 2026-10-14

demo PDF device-link/push урсгалаас илэрсэн дутагдал — additive:

- **`ValidateSign(r, digest, hash, opts ...ValidateSignOptions)` — `ExpectedFlowType`** (additive: variadic, одоогийн
  дуудлагууд хэвээр хөрвөнө). Өгвөл хариуны `flowType` ЯГ таарах ёстой, эс бөгөөс `ValidateAuth`-тай ижил
  `*ValidationError` (`flowType X ≠ эхлүүлсэн урсгал Y (relay байж болзошгүй)`); нэгээс олон options → `*ValidationError`.
  Сонголтгүй / хоосон бол одоогийн зан. Яагаад: demo PDF device-link/push урсгалд flowType-ийг гараар тулгаж байсан
  (TS SDK 0.9.1-тэй ижил). RAW_DIGEST_SIGNATURE-д `flowType` гарын үсэгт ордоггүй — хариуны тулгалт.
- Шалгасан: `gofmt -l .`, `go vet ./...`, `go test -race ./...`.

## 0.1.0 — 2026-10-14

Анхны хувилбар — TypeScript SDK (`@gerege-systems/eid-mongolia-sdk` 0.8.1)-тэй функциональ ижил, Go idiom, зөвхөн
стандарт сан (Go ≥ 1.22).

- **RP-API client** (`eid.NewClient`): `Auth` (push `NotificationByEtsi/ByDocument`, device link
  `DeviceLinkAnonymous/ByEtsi`; `CallbackURL`, `OnBehalfOf`, алгоритм/hash сонголт), `Sign` (`DigestByEtsi/ByDocument`,
  `TextByEtsi`), `PDF` (PAdES `Prepare` multipart — `Digest` хоёр урсгалд (CA !332), `Interactions` device-link-д, `Document`), `Organization`
  (`GetRepresentations`), `Session` (`Poll`, `WaitForResult`), `ParseSessionResult`. Бүх дуудлага `context.Context`;
  Bearer secret, timeout, `HTTPClient` (mTLS). `ResolveBaseURL` — анхдагч `https://rp.eidmongolia.mn`, хуучин `ca.`
  хост тодорхой алдаа.
- **Төрөлжсөн алдаа** (`errors.As`): `AuthenticationError`, `ForbiddenError{Code}`, `APIError{Status,Body,Code}`,
  `NetworkError{Timeout}` (Unwrap), `SessionFailedError{EndResult}`, `ValidationError`, `DeviceLinkError`;
  `OnBehalfErrorCodes`.
- **Device link v3** (`BuildDeviceLink`, `TickQRDeviceLink`) — HMAC-SHA256 `authCode`, QR `elapsedSeconds`; CA-ийн 15
  golden вектортой байт-ижил. Legacy `/dl?sessionId&vc` оруулаагүй (сервер 2026-10-07-нд хассан).
- **Validator** — гинж (trust anchor = `NationalRootCAPEM`, issuer нэр + AKI/SKI + CA + гарын үсэг + хугацаа),
  хугацаа/`ClockSkew`, `RequiredLevel`, ACSP_V2 / prehashed digest гарын үсэг (`rsassa-pss`, `shaNNNWithRSAEncryption`,
  `ecdsa-with-SHA256` — зөвхөн EC P-256 + SHA-256, TS 0.9.0-тэй ижил), алгоритм ↔ түлхүүрийн төрөл тулгалт, `ExpectedFlowType` /
  `UserChallengeVerifier` (relay хаалт), `SignedCallbackURL`, `CheckRevocation` (OCSP/CRL hook, hard/soft-fail).
  Хариунд `Subject` (`ParseSubject`: GivenName, Surname, CommonName, SerialNumber, Country).
- `DocumentVerified` — татсан PDF-ийн SHA-256 = session-ий `pdf.outSha256` (READY).
- Крипто туслах: `SHA256Base64`, `RandomChallenge`, `InteractionsToBase64` (JS `JSON.stringify`-тай байт-ижил),
  `BuildACSPV2Payload`, `ACSPV2Digest`, `UserChallengeOf`, `VerifyPayloadSignature`, `VerifyPrehashedSignature`.
- **`oidc` багц** — «eID-ээр нэвтрэх»: `Discover` (1 цаг cache, issuer яг тулгалт), `CreateAuthorization`
  (state/nonce/PKCE S256, `Display`), `HandleCallback` (state constant-time, RFC 9207 `iss`, алдааны код, token солих
  `client_secret_basic` RFC 6749 §2.3.1), `VerifyIDToken` (ES256, JWKS cache + танихгүй `kid` нэг refetch, iss / aud /
  azp / exp / iat ±60с / nonce / sub), `Claims`, `PKCEChallenge`, `Error{Code,Description}`.
- Шалгасан: `go vet`, `go test -race` (Go 1.22 + stable CI), staticcheck; TS SDK 0.8.1-тэй санамсаргүй 300 device
  link, 60 ACSP payload/digest, 100 interactions байт-ижил, гарын үсэг хоёр чиглэлд verify.
