# Changelog

## 0.1.5 — 2026-10-14

Эрхийн төрөл ба эх үүсвэрийн нэр (`rightTypeLabel`, `sourceLabel`, CA !344) — TS SDK 0.12.1-тэй ижил, additive:

- **`RightTypeLabel` / `SourceLabel`** (CA !344, additive) — `Representation.RightTypeLabel`, `Representation.SourceLabel`
  (`GetRepresentations`) ба session-ий `OrgResult.RightTypeLabel` (`OnBehalfOf`; тэнд `Source` байхгүй),
  `json:"…,omitempty"`. Эрхийн төрөл (ADMIN → «Админ» / Administrator, MANAGER → «Гарын үсэг зурагч» / Signatory) ба
  эх үүсвэрийн (REGISTRY → «Улсын бүртгэл» / State registry, MANUAL → «Захирал нэмсэн» / Added by the director) хүнд
  харуулах нэр, CA нэг газраас (`orgrole.RightTypeLabel` / `SourceLabel`, CA `docs/ORG_LOGIN.md` §4а); хэл нь
  `RoleLabel`-тэй ижил (`Config.Language` → `Accept-Language`). Клиент `RightType`/`Source` кодыг өөрөө орчуулахгүй.
  Хуучин CA-д хоосон. README: «RoleLabel / RightTypeLabel / SourceLabel». TS SDK 0.12.1-тэй ижил.
- Шалгасан: `TestRightTypeSourceLabel` (representations / session decode, хуучин хариунд хоосон, omitempty).
  `gofmt`, `go vet`, `go test -race`, `GOOS=linux go build`.

## 0.1.4 — 2026-10-14

Албан тушаалын нэр (`roleLabel`, CA !339) — TS SDK 0.12.0-тэй ижил, additive:

- **`RoleLabel`** (CA !339, additive) — `Representation.RoleLabel` (`GetRepresentations`) ба session-ий
  `OrgResult.RoleLabel` (`OnBehalfOf`), `json:"roleLabel,omitempty"`: албан тушаалын хүнд харуулах нэр, CA нэг газраас
  (`server/internal/orgrole`, CA `docs/ORG_LOGIN.md` §4а) өгнө. `Role` нь машин утга (`ceo` / `founder` / `stakeholder`
  эсвэл MANUAL текст) — клиент өөрөө орчуулахгүй, `RoleLabel`-ийг харуулна. Хуучин CA-д хоосон.
- **`Config.Language`** — дуудлага бүрд `Accept-Language` (`"mn"` | `"en"`); `""` = илгээхгүй (сервер mn). TS SDK
  0.12.0-ийн `language`-тэй ижил.
- Шалгасан: `TestRoleLabel` (representations / session decode, хуучин хариунд хоосон, omitempty), `TestLanguageHeader`
  ("" → header алга, "en", " mn " → "mn"). `gofmt`, `go vet`, `go test -race`, `GOOS=linux go build`,
  `go test -tags contract` (live).

## 0.1.3 — 2026-10-14

Порталын (eid-mongolia-mn !140) SDK шилжилтийн үлдэгдэл — TS SDK 0.11.0-тэй ижил:

- **Validator гинж → `x509.Certificate.Verify`** (аюулгүй байдал, High). Өмнө гинжийг гараар угсардаг байсан тул
  pathLenConstraint, name constraints, завсрын CA-ийн EKU, CA-ийн keyCertSign, үл таних critical extension шалгагддаггүй
  байв (портал өмнө нь x509.Verify-аар шалгадаг байсан — SDK руу шилжихэд регресс). Одоо `Roots` = trust anchor,
  `Intermediates` = `IntermediatesPEM`, `KeyUsages`: auth → clientAuth, sign → emailProtection (CA `ca_profile.go`:
  P-CITIZEN-AUTH = clientAuth+emailProtection, P-CITIZEN-SIGN = emailProtection), `CurrentTime` = leaf-ийн хугацаанд
  хавчсан мөч (`ClockSkew`). `AllowedIssuerSKIs`, `CheckKeyUsage`, revocation hook — хэвээр, Verify-ийн дараа.
  **Зан төлөвийн өөрчлөлт:** EKU-г `CheckKeyUsage`-ээс үл хамааран гинжийн шалгалт шалгана — гарын үсгийн
  (emailProtection-only) гэрчилгээ `ValidateAuth`-д татгалзагдана. certificatePolicies шалгахгүй (Go 1.22) — CA-ийн
  гинжинд policyConstraints / inhibitAnyPolicy алга. Алдааны текстэд subject орохгүй (шалтгааны ангилал л).
- **`Config.PDFMaxBytes`** (`DefaultPDFMaxBytes` = 64 MiB) — `PDF.Document` / `PDF.TokenDocument`; хэтэрвэл
  **`*ResponseTooLargeError`** (`Op`, `Limit`). JSON хариу 4 MiB-ээс хэтэрвэл мөн `*ResponseTooLargeError` (өмнө нь
  таслагдаад задлалтын алдаа болдог байсан).
- **`RepresentationsResponse.Raw`** — `GetRepresentations`-ийн түүхий JSON.
- **USB токены PAdES:** `PDF.TokenPrepare` (multipart, токены SIGN гэрчилгээ + `OnBehalfOf`), `PDF.TokenFinalize`
  (түүхий r||s 64 байт), `PDF.TokenDocument` — CA `docs/PADES_SIGNING.md` §16.5, `TOKEN_CERT.md`. Замууд CA-д бий ч
  `/.well-known/eid`-д алга тул `rpRoutesUndiscovered` (гэрээний тест WARN).
- Шалгасан: бодит гинж (01→02→03→04) ба CA-ийн бодит иргэний AUTH/SIGN (RSA + токены EC) гэрчилгээнүүд Go
  `x509.Verify`-аар амжив (репод оруулаагүй — хувийн мэдээлэлтэй); тест: бодит профайлын хуулбар гинж амжина,
  pathLen / завсрын EKU / CA:false / keyCertSign-гүй / хугацаа дууссан завсрын / буруу root / MDDC дутуу / name
  constraints / үл таних critical extension → татгалзана; 04 ← 03 бодит гэрчилгээ x509.Verify. `gofmt`, `go vet`,
  `go test -race` (1.25 + 1.22), `GOOS=linux go build`, `go test -tags contract` (live).

## 0.1.2 — 2026-10-14

Порталыг (eid-mongolia-mn, MR !140) SDK руу шилжүүлэхэд илэрсэн дутагдлууд — бүгд additive (TS SDK 0.10.0-тэй ижил):

- **`SessionResult.Person`** (CA `person` блок: `FirstName`/`LastName`(эцгийн)/`FamilyName`(ургийн овог), `…En`,
  `CivilID`, `RegNo`, `BirthDate`, `Gender`, `GeID`), **`SessionResult.Raw`** (түүхий JSON), **`TokenCertificate`**
  блок; `PersonMatchesCertificate(person, subject)` — person блок гарын үсэгт ордоггүй тул `PNOMN-<civilId>` тулгалт.
- **`APIError` / `ForbiddenError`: `RetryAfter`** (Retry-After секунд эсвэл HTTP-огноо задалсан) **+ `Header`**;
  `APIError.Retryable()`, кодууд `CodePDFPrepareBusy`, `CodeDocumentPending`, `CodeTSAUnavailable`,
  `CodeLTVUnavailable`, `CodeRateLimited`, `CodeStateUnavailable`, `CodeIssuancePending` (`RetryableCodes`).
  **`Config.PDFTimeout`** (анхдагч `DefaultPDFTimeout` = 80s; өмнө нь тогтмол 60s).
- **`SignOptions.FileName`** → хүсэлтийн `fileName` (CA `NotificationSignRequest.FileName`).
- **`Client.Person`** (PKI_READ): `Certificates`, `Devices`, `Activity(ActivityQuery)`, `Summary`, `Children`.
  **`Client.Token`**: `IssueCertificate` (CA-ийн CSR hash тулгалттай), `CertificateResult`, `VerifyTokenCertificates`,
  `AuthChallenge`, `AuthVerify` (endResult + identity.etsi = гэрчилгээний SERIALNUMBER), `TokenAuthDigest` (TOKEN_AUTH
  тест вектор), `TokenLimitOf`.
- **Validator**: `TrustConfig.AllowedIssuerSKIs` (+ `CitizenIssuingCASKI`), `CheckKeyUsage` (auth → clientAuth,
  sign → nonRepudiation), `SchemeName`; `CheckRevocationStatus` → `good` / `unchecked` / `skipped` (+ алдаа).
- **PII**: `NetworkError.Op` замыг `/etsi/…`, `/document/…` болгож, `Err`-д `*url.Error`-ийн оронд шалтгааныг
  (бүтэн URL-гүй) хадгална; хариу задрахгүй алдааны зам мөн; гэрчилгээний хугацааны алдаа CN биш serial-аар.
- **`AuthenticationError`**: `Code`, `Message`, `Body`, `Header` (CA-ийн 401 vs proxy-ийн 401).
- Гэрээ: `routes.go`-д person ×5, token/certificate ×2; `/token/auth/*` CA-д байгаа ч discovery-д алга тул
  `rpRoutesUndiscovered` (гэрээний тест WARN).
- **Гэрээний шалгалт** (`go test -tags contract`, `.github/workflows/contract.yml` — PR / main / өдөр бүр): SDK-ийн
  RP-API зам бүр live `/.well-known/eid`-д, OIDC утгууд (issuer, ES256, S256, client_secret_basic, `Claims` талбарууд)
  `openid-configuration`-д таарахыг шалгана; SDK хамраагүй discovery замууд WARN. RP-API замууд `routes.go`-д нэг
  газар төвлөрсөн (зан төлөв өөрчлөгдөөгүй). Энгийн `go test` сүлжээгүй хэвээр.
- Шалгасан: `gofmt -l .`, `go vet ./...` (1.25 + 1.22), `go test -race ./...`, `go test -tags contract` (live).

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
