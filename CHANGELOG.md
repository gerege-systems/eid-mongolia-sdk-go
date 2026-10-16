# Changelog

## v0.6.0 — 2026-10-16

### ⚠️ BREAKING — аюулгүй анхдагч (SDK Багц 2, TS 0.19.0-тэй 1:1)

- **Гэрчилгээний зориулалт анхдагчаар шалгагдана** (өмнө `CheckKeyUsage: false` анхдагч). Нэвтрэлтийн (PIN1,
  P-CITIZEN-AUTH) түлхүүрийн гарын үсэг `ValidateSign`-д тэнцдэг байсан (AUTH гэрчилгээнд EKU emailProtection бий тул
  `x509.Verify`-аар өнгөрдөг байв) — одоо KU nonRepudiation алга гэж татгалзана. Унтраах: `SkipKeyUsageCheck: true`
  (шинэ, зөвлөхгүй); `CheckKeyUsage` — deprecated, нөлөөгүй (эвдэхгүйн тулд үлдсэн).
- **`AllowedIssuerSKIs` анхдагч `[]string{CitizenIssuingCASKI}`** (TrustAnchorsPEM тохируулсан үед). Ижил root-ийн
  доорх өөр CA (байгууллагын 05 г.м.)-ийн гэрчилгээ иргэнийх гэж тэнцэхгүй. Унтраах: `AllowAnyIssuer: true` (шинэ);
  жагсаалт өгвөл түүгээр шалгана.
- **Түвшин гэрчилгээнээс** (`CertificateLevelOf`, шинэ): SIGN-д qcStatements QcCompliance → QUALIFIED (+ QcSSCD → QSCD),
  qcStatements-гүй → ADVANCED; AUTH-д (CA qcStatements бичдэггүй) KeyUsage keyEncipherment (утасны профайл) →
  QUALIFIED, үгүй (токен) → ADVANCED. Хариуны утга гэрчилгээнийхээс өндөр бол `*ValidationError`, бага бол хариуных.
  `VerifiedIdentity` / `VerifiedSignature` / `Signer`-ийн `CertificateLevel` = энэ утга. Хариунд түвшин алга бол
  гэрчилгээнийх (өмнө татгалздаг байв).
- **`Token.AuthVerify(ctx, ch *TokenAuthChallenge, certDER, signature)`** — эхний аргумент challenge (өмнө
  `challengeID string`). SDK CA-ийн OK-д дангаар итгэхгүй: `ch.RPUUID` = энэ RP, r||s нь
  `TokenAuthDigest(RPUUID, Challenge)` дээр гэрчилгээний түлхүүрээр таарах, гэрчилгээ `Config.Trust`-аар (хугацаа,
  KU/EKU auth, гинж, issuer) хүчинтэйг CA руу илгээхээс өмнө шалгана.
- **`eidlogin`: `start` анхдагч хязгаар** нэг IP-ээс 60 с-д 20 (`DefaultRateLimit()["start"]`; `ClientIP` өгсөн бол).
  Унтраах: `RateLimits: map[string]RateRule{"start": {}}`.

### Засвар / нэмэлт

- `eidlogin` санах ойн хязгаарлагч: 10 000 түлхүүрээс хэтэрвэл map-ийг бүхэлд нь цэвэрлэдэг байсныг (10k өөр түлхүүрээр
  дүүргэж тухайн дугаарын push хязгаарыг тойрох боломжтой байв, `eidlogin.go` windowLimiter) — цонх нь өнгөрсөнийг
  цэвэрлээд, дүүрэн хэвээр бол шинэ түлхүүрийг татгалзана.
- `eidlogin.NewMemoryStore()` ≤ `MemoryStoreMax` (10 000): дүүрвэл `ErrStoreFull`, start 503 `{"error":"busy"}`;
  эхэлсэн нэвтрэлтийг устгахгүй.
- `CitizenIntermediatesPEM` (02 → 03 → 04, `pades/internal/eidcrypto/chain`-тэй байт-ижил — тестээр тулгана);
  `IntermediatesPEM` nil бол анхдагч — README-ийн `TrustConfig{TrustAnchorsPEM: []string{NationalRootCAPEM}}` жишээ шууд
  ажиллана (өмнө `intermediates` хувьсагч тодорхойгүй, өгөхгүй бол гинж тасарна).
- **`pades.Complete`: LTV retry** (TS 0.18.3-тай ижил) — OCSP/CRL цуглуулалт унавал ижил state, гарын үсэг, TSA
  timestamp-аар өөрөө дахин оролдоно: `CompleteOptions.LTVRetries` (`*int`; nil = `DefaultLTVRetries` 2, нийт 3, хүлээлт
  ~1 с, ~3 с + 0–25% jitter; 0 — унтраах; 0–10-аас гадуур → `REQUEST_INVALID`); бүгд унавал `LTV_UNAVAILABLE`; ctx
  цуцлалт хүлээлтийг тасална. PIN дахин асуухгүй. Портал (eidmongolia) өөрийн retry-г (!161) устгахаар төлөвлөж байна.
- **`NewOCSPChecker`: олгогч өөрөө зурж, хариундаа ӨӨРИЙН гэрчилгээг шигтгэсэн OCSP хариу** (RFC 6960 §4.2.2.2-оор
  хүчинтэй) `x/crypto/ocsp`-д «bad OCSP signature» гэж татгалзагддаг байв (шигтгэсэн cert-ийг issuer-ээр зурагдсан байхыг
  шаарддаг). Шигтгэсэн cert нь issuer мөн (байт-ижил эсвэл subject+SPKI — дахин олгосон хуулбар) бол хариуг issuer-ийн
  түлхүүрээр шалгана; delegated responder (EKU OCSPSigning) зам хэвээр, өөр түлхүүрээр зурсан бол signature алдаа.
  Хаана: `ocsp.go`; тест `TestOCSPIssuerSignedEmbeddedIssuer` (засваргүйгээр унадгийг шалгасан). Портал түр
  `ocsp_issuer_signed.go` transport-оор тойрч байгаа — **v0.6.0-аас тойрох шаардлагагүй**.
- Contract тест: discovery-ийн `pdfSigning.registerErrorCodes` == `PDFRegisterErrorCodes` (олонлогоор); CA-д талбар
  гарахаас өмнө skip + WARN.
- `PDF.RegisterSignature`-ийн 80 с (`DefaultPDFTimeout`) хэвээр; TS 0.19.0 ижил болсон (өмнө TS 15 с).

Шилжих: `AuthVerify(ctx, ch.ChallengeID, …)` → `AuthVerify(ctx, ch, …)`; `CheckKeyUsage: true`-г устгаж болно (нөлөөгүй);
тест/dev-ийн өөр CA-тай орчин → `AllowAnyIssuer: true`.

Хаана: `validator.go`, `certchoice.go`, `roots.go`, `token.go`, `client.go`, `eidlogin/eidlogin.go`, `pades/complete.go`,
`contract_test.go`, README, `doc.go`.
Шалгасан: `go vet ./...`, `go test ./...`, `go test -tags contract -run Contract .` (4 pass, 1 skip),
`GOOS=linux GOARCH=amd64 go build ./...`. Шинэ тест: PIN1 гарын үсэг ValidateSign-д унах, анхдагч issuer,
`TestCertificateLevelFromCertificate`, `TestCitizenIntermediatesPEM`, token auth-ийн локал шалгалт (CA руу явахгүй),
`TestDefaultStartLimit`, `TestWindowLimiterFullFailsClosed`, `TestMemoryStoreCap`, `TestCompleteLTVRetry` (2 унаад 3 дахь
нь golden-той байт-ижил; 3 унавал LTV_UNAVAILABLE; 0; -1/11; ctx cancel).
Прод DB (read-only, 2026-10-16): идэвхтэй утасны SIGN 66/66 QcCompliance-тэй, AUTH 67/67 KU DS|KE, токен AUTH 3 KU DS,
токен SIGN 3 qc-гүй — бүгд «eID Mongolia Issuing CA»-аас; анхдагч солигдсоноор одоогийн иргэд унахгүй.

## v0.5.2 — 2026-10-16

### Нэмэгдсэн

- **`POST /pdf/signatures`-ийн `Code*` тогтмолууд ба `PDFRegisterErrorCodes`** — CA main `pades_register.go`,
  `handlers_pdf.go` (2026-10-16)-ийн бүх код: `CodeRequestTooLarge`, `CodeCMSInvalid`, `CodeSignatureInvalid`,
  `CodeTimestampInvalid`, `CodeSignerMismatch`, `CodeSignerCertInvalid`, `CodeTokenCertInvalid`, `CodeTokenOrgMismatch`,
  `CodeSessionMismatch`, `CodeSessionNotComplete`, `CodeSessionFailed`, `CodeClaimedRoleMismatch`, `CodeDocIDConflict`,
  `CodeRegistryConflict`, `CodeDocNotFound`, `CodePriorMismatch` (+ одоо байгаа `CodeRequestInvalid`,
  `CodeRepresentationRevoked`, `CodeRateLimited`, `CodeStateUnavailable`). Яагаад: TS SDK 0.18.3-ийн
  `PDF_REGISTER_ERROR_CODES`-тэй нийцүүлэх (contract журам). Хаана: `pdfregister.go`.

Шалгасан: `go vet ./...`, `go test ./...` (шинэ `TestPDFRegisterErrorCodes`), `GOOS=linux GOARCH=amd64 go build ./...`.

- **`NewOCSPChecker` (портал өөрийн ocsp.go-г үүгээр солиход):**
  - `OCSPOptions.Observe func(OCSPObservation)` — шалгалт бүрд (кэшээс ч) `Status`, `Responder` URL, `Duration`, `Cached`,
    `Err`; serial/нэр орохгүй.
  - Хариугүй үед `RevocationUnknown` + `*OCSPError` (`Kind`: no_responder / no_issuer / timeout / network / http_status
    (+`HTTPStatus`) / responder_status / parse / signature / invalid; `errors.Is(err, ErrOCSPNoAnswer)`). Өмнө нь
    `RevocationUnknown, nil` — шалтгаангүй. `Validator.CheckRevocationWith` үүнийг unknown-оор горимоор шийднэ (soft →
    `unchecked`, nil; hard → `*ValidationError{Cause}`; `ValidationError.Unwrap` нэмэгдсэн) — `eidlogin`-ий зан хэвээр.
    **Анхаар:** checker-ийг шууд дууддаг код одоо `err != nil` авна (status нь `RevocationUnknown` хэвээр).
  - Кэш = min(`CacheTTL` (анхдагч 5 мин; сөрөг = кэшгүй), хариуны `NextUpdate` − одоо).
  - Delegated responder (RFC 6960 §4.2.2.2): ocsp.eidmongolia.mn-ийн бодит хариу (санамсаргүй serial, status unknown,
    «eID OCSP Responder» шигтгэсэн, EKU OCSPSigning) `testdata/ocsp-eid-delegated.der`-ээр тест — x/crypto
    `ParseResponseForCert` болон SDK-ийн шалгалт аль хэдийн зөвшөөрдөг байсныг баталгаажуулав (татгалзалт
    давтагдаагүй); өөр олгогчоор → `signature`.
  Шалгасан: `go test ./...`, `go test -race -run 'OCSP|Revocation'` (шинэ: TestOCSPErrorKinds, TestOCSPObserveAndNextUpdateCache,
  TestOCSPRealDelegatedResponder; TestOCSPChecker typed алдаагаар шинэчлэгдсэн), eidlogin тестүүд ногоон.
### README: share «туг унтраалттай» тэмдэглэл хасав

- **Юу/яагаад:** CA (ca-eidmongolia-mn !374) `rp./share`-ийн туг хасагдаж үргэлж асаалттай; README-ийн callout ба 503
  мөрийг шинэчлэв. Код өөрчлөгдөөгүй — `SHARE_DISABLED` код хуучин CA-д нийцүүлж хэвээр.
- **Шалгасан:** зөвхөн README; `grep -n "унтраалттай" README.md` — 0.

## v0.5.1 — 2026-10-16

### Нэмэгдсэн — токены сунгалтын scope түгжээ: TOKEN_SCOPE_CHANGE (CA !373)

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

## v0.5.0 — 2026-10-16

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

## v0.4.0 (BREAKING) — 2026-10-15

- **v0.4.0 (BREAKING): PDF upload клиент устсан.** CA upload-д суурилсан PDF endpoint-уудыг устгасан (`POST
  /pdf/sign/prepare`, `GET /pdf/sign/{id}/document`, `/pdf/token/prepare|{id}/finalize|{id}/document` → 404;
  discovery `endpoints.pdf`-д зөвхөн `signatures`), session-ий `pdf` блок, `PDF_PREPARE_BUSY` / `DOCUMENT_PENDING`
  кодууд ч CA-д алга. SDK тэдгээрийг дуудсаар байсан тул `contract` CI улаан байв. TS SDK 0.15.0-тэй нийцүүлэв.
  Tag энэ PR-д үгүй — PR #18 (visible signature)-тэй хамт v0.4.0.
  - Устсан exported: `PDFService.Prepare`, `.Document`, `.TokenPrepare`, `.TokenFinalize`, `.TokenDocument`;
    `DocumentVerified`; `PDFPrepareInput`, `PDFPrepareSession`, `PDFDeviceLink`, `PDFSignerRef`, `PDFFlowNotification`,
    `PDFFlowDeviceLink`, `PDFTokenPrepareInput`, `PDFTokenPrepareSession`; `SessionResult.PDF`, `PDFSessionBlock`,
    `PDFSigner`, `PDFValidation`, `PDFPending` / `PDFReady` / `PDFFailed` / `PDFExpired`; `Config.PDFMaxBytes`,
    `DefaultPDFMaxBytes`; `CodePDFPrepareBusy`, `CodeDocumentPending` (`RetryableCodes`-оос ч).
  - Үлдсэн (клиент талын PAdES): `pades/`, `PDFService.RegisterSignature` (`POST /pdf/signatures`),
    `PDFSignatureRegistration`, `PDFMedium*`, `Sign.DigestForSigner` / `DeviceLinkForSigner`, certificate-choice.
    `Config.PDFTimeout` / `DefaultPDFTimeout` одоо зөвхөн `RegisterSignature`-д.
  - Шилжилт: `PDF.Prepare` → `Document` → `DocumentVerified`-ийн оронд `pades.Prepare` → `Sign.DigestForSigner` →
    `pades.Complete` → `PDF.RegisterSignature` (README §7). Токен: токен DTBS-ийг зурж `Medium: PDFMediumToken`.
  - Хаана: `pdf.go`, `pdftoken.go` (устсан), `routes.go`, `client.go`, `types.go`, `session.go`, `errors.go`,
    тестүүд (`client_test.go`, `portal_gaps_test.go` — түр алдааны тест `RegisterSignature` руу шилжсэн,
    `x509_gaps_test.go`, `routes_test.go`), README §3.4/§3.7/§5/English.
  - Шалгасан: `gofmt`, `go vet`, `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build ./...`,
    `go test -tags contract -run Contract` live discovery-тэй PASS (21 зам; `/token/auth/*` discovery-д орсон WARN —
    тусдаа).
- **PAdES: харагдах гарын үсэг (сонголттой) + golden v3 + гадны шалгалт (qpdf, pyHanko).**
  - Юу: `PrepareOptions.Appearance` (`page`, `x`, `y`, `width`, `height`, `lang`) — nil бол үл харагдах, v2 golden байт-ижил.
    Харагдах widget `/Rect` (CropBox-ийн харагдах эх, `/Rotate` 0/90/180/270), `/F 4`, `/P`, хуудасны `/Annots`-д
    (incremental), `/AP /N` form XObject (шахалтгүй, verify хуудасны фонт, өөрийн QR): нэр, үүрэг, «eID Mongolia-аар
    зурсан» / «Signed with eID Mongolia», огноо (+08), QR `https://ca.eidmongolia.mn/verify/<docID>/<revIndex>`.
    Дүрэм: `pades/APPEARANCE_SPEC.md` (хэмжээ/тойруулга/wrap/жижгэрэх, багтахгүй → `REQUEST_INVALID`, §5 validator).
  - Validator (own-signer): зөвхөн яг энэ widget + 11 /AP объектыг дахин үүсгэж байт-түвшинд тулгаж хүлээн авна; ObjStm
    доторх хуудсыг шууд объектоор дахин бичихийг (own, page/annots) зөвшөөрнө. Тайланд `visible` талбар.
  - DSS: давхардалгүй байдлыг (ижил DER → нэг stream, массивт нэг удаа; өмнөх DSS-ийн объектыг дахин ашиглах) PROFILE.md §7-д
    тодорхой бичиж, golden бүрд тест (`dssUnique`) — бичигч аль хэдийн ингэж ажилладаг тул гаралт өөрчлөгдөөгүй.
  - CI: `golden-external` job — golden гаралт бүрд `qpdf --check` ба pyHanko (INTACT/VALID/TRUSTED, DSS-ээс LT, timestamp,
    өөрчлөлтийн түвшин, харагдах).
- Хаана: `pades/prepare.go`, `pades/internal/core/{appearance,signature,vpage}.go`, `pades/internal/validate/{appearance,
  revisions,extract,validate}.go`, `pades/internal/padestest`, `pades/{APPEARANCE_SPEC,PROFILE}.md`, `pades/testdata/golden`
  (manifest + 5 тохиолдол, `input/quartz-rotated90.pdf`, `ci/pyhanko_check.py`), `.github/workflows/ci.yml`, README.
- Шалгасан: `TestGolden` (v2 тохиолдлын гаралт өөрчлөгдөөгүй — git diff), `TestOwnVisibleSignature` (хүлээн авах + 17
  халдлага), `TestAppearanceRejects`, `TestVisibleRect`, `TestNum100`; pdfsig (Signature is Valid), qpdf --check,
  pyHanko 0.37 (19 гарын үсэг OK), pdftoppm/PDFKit render, QR-ийг CIDetector-оор уншсан; gofmt, vet, `go test -race ./...`,
  linux build.
- Үлдсэн: CA `server/internal/validate`-д §5-ийг порт (тусдаа агент); native SDK-ууд (TS/Swift/Kotlin/.NET) v3 golden;
  PDFKit (macOS) `/Rotate`-тэй хуудсан дээрх widget-ийг зурдаггүй (poppler зурна) — шалгах.
- **Баримт/тайлбарын зөрүү (аудит 2026-10-15) + CHANGELOG нэгтгэл, guard.**
  - README: install `@v0.4.0`; хамаарал — `eid`/`eidlogin` стандарт сан + `golang.org/x/crypto/ocsp`, `pades` мөн
    `golang.org/x/text`; багцын зам `…/eid-mongolia-sdk-go/eidlogin`; RP бүртгэл — өргөдлийн API
    (`POST /v3/rp-applications`) засвартай (503 `rp_applications_maintenance`), имэйлээр; товчны CDN `@0.15.4`;
    `/token/auth/*` live discovery-д (`endpoints.token.auth_challenge` / `auth_verify`); `REPRESENTATION_REVOKED` =
    `RegisterSignature` ба токены гэрчилгээ олголт. `routeTokenAuth*` → `rpRoutes` (гэрээний тест fail-аар шалгана).
  - **BREAKING (v0.4.0-д):** `eid.CodeTSAUnavailable`, `eid.CodeLTVUnavailable` хасагдсан, `RetryableCodes`-оос ч — CA
    тэдгээрийг буцаадаггүй (CA main `af939ab0`-д шалгасан); клиент талын `pades.CodeTSAUnavailable` /
    `pades.CodeLTVUnavailable` хэвээр. Кодгүй 429/503 + `Retry-After` `Retryable()` хэвээр.
  - Тайлбар: `errors.go` (устсан `PDF_PREPARE_BUSY` / `DOCUMENT_PENDING` / document route-ийн дурдлага), `doc.go` /
    `client.go` (`eid` PDF угсрахгүй — зөвхөн `RegisterSignature`; угсралт = `pades`), `eidlogin.Identity.DocumentNumber`
    = төхөөрөмжийн UUID, `pades/doc.go` (байхгүй mobile/capi/wasm binding), `pades/WIRE.md` (golden nonce = §4).
  - `CHANGELOG.md`: v0.1.6 … v0.3.2 фрагментуудыг tag-аар тулгаж нэгтгэв (sign-session-gaps → v0.2.1; «CA хугацаа
    буцаадаггүй» нь v0.2.2-оос хуучирсныг тэмдэглэв); v0.4.0 (BREAKING) — Unreleased.
  - Guard: `scripts/changelog.sh` (`assemble` / `check-release` / `check-pr`); CI `changelog` job PR-д фрагмент шаардана;
    `.github/workflows/release.yml` — `v*` tag-д фрагмент үлдсэн, гарчиг алга эсвэл «Unreleased» бол улаан.
  - Шалгасан: live `/.well-known/eid`, `/mobile/app-config`, `/v3/rp-applications` (2026-10-15); `gofmt`, `go vet`,
    `go test ./...`, `GOOS=linux GOARCH=amd64 go build ./...`.

## 0.3.2 — 2026-10-14

- **v0.3.2 — `eidlogin`: регистрийн oracle хаалт (decoy + PushFloor), OCSP цуцлалт, аудитын hook (TS 0.15.2-тэй ижил).**
  - **G1 (Critical) — бүртгэлийн oracle.** Push start eID-ийн татгалзалд (танихгүй дугаар) 502, бүртгэлтэйд 200 өгдөг,
    хугацааны доод хязгааргүй байсан — нэвтрээгүй хэн ч регистр eID-д бүртгэлтэй эсэхийг шалгаж болох байв. Одоо eID-ийн
    өөрийн JSON 4xx (401/403/429-ээс бусад) → decoy session: бодит хариутай ижил `{mode, vc (5 оронтой), expiresIn}`,
    ижил cookie, `status` нь eID-ээс асуулгүй `Poll`-ын хугацаанд барьж PENDING → TTL-ийн дараа EXPIRED. Push start-ийн
    хариу бүр (бодит, decoy, 502) ≥ `PushFloor` (анхдагч 1 с, ctx тасарвал зогсоно). 5xx / холболт / JSON бус 4xx (proxy)
    / 401 / 403 → 502, 429 → 429 (eID порталын `HandleEIDStartByNationalID`-тэй ижил: тасалдлыг нуухгүй, дугаараас
    хамааралгүй). Хязгаар decoy-д ч үйлчилнэ. Push-ийн CA `TIMEOUT` → `EXPIRED` (decoy-той ижил төгсгөл). Унтраах: `DisableDecoy`, `DisablePushFloor` (анхааруулгатай).
  - **G2 (High) — цуцлалт.** `finish` нь `ValidateAuth`-ийн дараа гэрчилгээг AIA OCSP-оор шалгана (`Config.Revocation`,
    nil = шинэ `eid.NewOCSPChecker`). revoked / unknown → FAILED `VALIDATION` (500 биш); хариугүй → soft-fail
    (порталын `EID_OCSP=soft`: зөвшөөрч Warn, `Identity.Revocation = unchecked`), `RevocationMode: eid.RevocationHardFail`
    → FAILED. `DisableRevocation` — унтраана. Шинэ: `eid.NewOCSPChecker` (олгогч/OCSPSigning responder-ийн гарын үсэг,
    serial, thisUpdate [−48ц, +5мин], nextUpdate, 2 с timeout, redirect-гүй, 16 KiB, good-ийг 5 мин кэш),
    `Validator.CheckRevocationWith`, `Identity.Revocation`.
  - **G3 (Medium) — аудит.** `Config.OnEvent(ctx, kind, sessionID, meta)`: `push_sent` (meta `decoy`), `push_limited`,
    `refused`, `expired`, `unverified` (`reason`), `flow_refused`, `success` (`flow`, `revocation`), `failed`
    (`endResult`). Регистрийн дугаар биш `pushKey` = HMAC-SHA256(`AuditKey`, дугаар); токен/нууц орохгүй.
- Хаана: `ocsp.go`, `validator.go`, `eidlogin/eidlogin.go`, `eidlogin/security_test.go`, `ocsp_test.go`,
  `eidlogin/eidlogin_test.go` (хуурмаг цаг, event бүртгэл), `README.md` §2, §4.
- Шалгасан: `TestPushDecoyIndistinguishable` (талбар, vc хэлбэр, floor 1 с хуурмаг цагаар, decoy poll eID-ээс асуухгүй,
  EXPIRED, event-д decoy, meta-д регистр алга), `TestPushOutageNotDecoy` (500/proxy400/401 → 502), `TestDecoyAndFloorOptOut`,
  `TestDecoyRateLimited`, `TestRevocation` (revoked/checker алдаа/hard-fail → FAILED VALIDATION; анхдагч soft → unchecked;
  good; disabled), `TestEvents`, `TestOCSPChecker` (good/revoked/unknown, delegated responder, хуучин thisUpdate, 5xx,
  буруу issuer, кэш); `gofmt`, `go vet`, `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build ./...`.
- **PAdES бүртгэл: горим A-ийн өмнөх гарын үсэгтэй баримт + `Created`.**
  - Юу: горим A-аар (CA угсарсан) эхэлж зурагдсан баримтад нэмж зурахад `RegisterSignature` 409 `PRIOR_MISMATCH` авдаг
    байв — `pades.Registration` бүх өмнөх мөрийг CMS-ээр илгээж, `PriorRevisionSHA256`-г дуудагчид гараар ангилуулдаг. CA
    өмнөх мөр бүрийг өөрийнх нь түлхүүрээр таньдаг (клиент — `cms_sha256`, горим A — `sig_rev_sha256` = `sha256(doc[0 :
    ByteRange[2]+ByteRange[3]])`; CA `persistence/models.go` `PDFPrior.Covers`, `pades_finalize.go` `sha256(signed)`), файлаас
    ялгах боломжгүй (профайл 1:1).
  - Засвар: `pades.Registration` → `PriorSignatures []eid.PDFPriorSignature` (`json:"-"`, CA руу илгээхгүй);
    `RegisterSignature` эхлээд CMS-ээр, `PRIOR_MISMATCH` бол эхний k-г revision-оор (k = 1…n), n ≤ 4 бол бүх хослол
    (`priorSplits`, TS-тэй ижил дараалал). `PriorRevisionSHA256` гараар өгвөл хуучин зан.
  - `PDFSignatureRegistered.Created` — 201 → true, 200 (давталт) → false (`httpDoer.postJSONStatus`).
- Хаана: `pdfregister.go`, `client.go`, `pades/register.go`, README.
- Шалгасан: `TestRegisterSignatureReplayAndPriorMismatch`, `TestPriorSplits`, `TestRegisterSignature` (Created),
  `pades` 2 дахь гарын үсэг: `PriorRevisionSHA256[0] == эхнийх SigRevSHA256`, `PriorSignatures`; gofmt, vet,
  `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build ./...`.
- Үлдсэн: native SDK (Swift/Kotlin/.NET)-д ижил засвар тусдаа.

## 0.3.1 — 2026-10-14

- **v0.3.1 — `eidlogin`: өөрийн хязгаар өгөхөд анхдагч push хязгаар алдагддаг байсан (TS 0.15.1-тэй зэрэгцүүлсэн).**
  - `Config.RateLimit` өгөхөд анхдагч (push — нэг дугаарт 3/мин, MFA fatigue) чимээгүй унтардаг байв. Одоо
    `Config.RateLimits map[string]RateRule` (`"start"` | `"push"`) `DefaultRateLimit()`-тэй төрөл тус бүрээр нэгтгэгдэнэ
    (`RateRule{Max, Window}` санах ойн цонх | `{Func}` | `{}` хязгааргүй); `Config.RateLimit` функц анхдагч ДЭЭР
    нэмэгдэнэ. `DefaultRateLimit()` export (шинэ map). Буруу түлхүүр / Window ≤ 0 → `New` алдаа.
  - README: хязгаарлалтын хэсэг, товчны CDN 0.15.1, dark токен (`--eid-<нэр>-dark`) заалт, install v0.3.1.
- Хаана: `eidlogin/eidlogin.go`, `eidlogin/eidlogin_test.go`, `README.md` §2.
- Шалгасан: `TestRateLimitsMergeKeepsDefaultPush` (зөвхөн start өгөхөд push 3/мин идэвхтэй), `TestRateLimitFuncAddsToDefault`,
  `TestRateLimitsOverridePush` (window/off/func, start window), `TestDefaultRateLimitAndValidation`; `gofmt`, `go vet`,
  `go test ./...` (+ `-race` eidlogin), `GOOS=linux GOARCH=amd64 go build`.

## 0.3.0 — 2026-10-14

### Клиент талын PAdES — Go reference (`pades`)

- **Юу:** CA-ийн PAdES бичигч (`server/internal/pdfsign/pades/*`) ба нийтийн шалгагч (`validate/*`)-ийг extract хийв:
  `pades.Prepare` (хөнгөн precheck → verify хуудас → R_sig → DTBS), `pades.Complete` (гарын үсэг шалгах → RFC 3161 →
  CMS → OCSP/CRL (AIA/CDP, genTime-ийн дараа) → DSS → self-validation) → `*Completed` (CA-ийн бүртгэлийн талбаруудтай),
  `pades.Verify` (CA-ийн /v3/validate/pdf-тэй ижил тайлан). Verify хуудас — хоёр хэлтэй (mn анхдагч, en), минимал детерминист writer + өөрийн QR
  (pdfcpu/fpdf/go-qrcode-гүй). Профайлын баримт: `pades/{PROFILE,PAGE_SPEC,PRECHECKS,WIRE}.md`.
- **Яагаад:** PDF eID-ийн серверт очихгүй (CA docs/PADES_CLIENT_SIDE.md); Go нь TS/Swift/Kotlin/C# native SDK-уудын
  reference, golden vector-оор байт-ижил байдлыг баталгаажуулна.
- **Хаана:** `pades/`, `pades/assets` (Noto Sans OFL, zlib тогтмол asset + metrics.json), `pades/internal/{core,qr,
  validate,eidcrypto,padestest}`, golden `pades/testdata/golden/`. `go.mod`: go 1.22 → 1.25 (тестийн хамаарал pdfcpu
  v0.12.0), CI matrix 1.25/stable.
- **CA-аас зөрөх:** xref stream шахалтгүй; шууд `/Info` trailer-т хуулна; `/M` үргэлж +08:00; verify хуудас шинэ writer;
  үндэсний CRL-ийг `https://crl.eidmongolia.mn/` толиноос татна;
  prepare-д validator биш хөнгөн precheck (бүртгэлийн оронд eID олгогч + SubFilter-ээр «гадны» гарын үсэг); цуцлалтын
  төлөв DSS-ийн OCSP/CRL-ээс; задлагч процесс дотор.
- **Шалгасан:** `go test -race ./...` (Go 1.25, 1.27), golden (prepare+complete байт-ижил), desktop Swift golden,
  e2e (RSA/ECDSA r‖s, DER), QR-ийг CoreImage-ээр, хуудсыг PDFKit-ээр уншиж (текст ToUnicode, QR decode) шалгав,
  `GOOS=linux GOARCH=amd64 go build ./...`.
- **Бүртгэл (CA §4.3/§4.3.1):** `eid.PDFSignatureRegistration` + `PDFService.RegisterSignature` (`POST /pdf/signatures`,
  CA dto-тэй ижил бие, `signerEtsi`), `pades.Registration(completed, opts)`; `Representation.ClaimedRole` (CA !352).
  RSASSA-PSS гарын үсгийг `Complete` `REQUEST_INVALID`-аар татгалзана (DigestForSigner/DeviceLinkForSigner-ийн анхдагч
  sha256WithRSAEncryption). README-ийн жишээ `pades/example_test.go`-оор compile хийгдэнэ; contract тест
  `TestContractPDFSignaturesBody` (discovery-ийн биеийн талбар = SDK-ийн JSON түлхүүр).

## 0.2.2 — 2026-10-14

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

## 0.2.1 — 2026-10-14

- **v0.2.1 — `eidlogin` засвар (TS 0.14.1-тэй зэрэгцүүлсэн; demo интеграцаас ирсэн асуудлууд).**
  - `Identity.SessionID` нэмэв (DocumentNumber, Certificate байсан) — RP дараагийн алхамд (гарын үсэг, гэрчилгээ холбох).
    Tx нь OnSuccess-оос өмнө атомар устгагдах (нэг удаа) хэвээр — баримтжуулав.
  - `ForwardedClientIP(hops)` (XFF баруунаас n, эсвэл X-Real-IP; hop дутвал "") ба `RemoteAddrIP` — `Config.ClientIP`-д
    бэлэн; TS-ийн `trustProxy`/`getClientIp`-тэй ижил дүрэм. `ClientIP` nil бол `New` нэг удаа Warn.
  - README: клиент IP, Redis store жишээ (go-redis, SDK хамааралгүй), eID аппын доод хувилбар (iOS 2.2.3 (59),
    Android 2.2.3 (60); app-config min iOS 2.2.7 / Android 83 — 10-14 шалгасан), товчны CDN 0.14.1.
- Хаана: `eidlogin/eidlogin.go`, `eidlogin/eidlogin_test.go`, `README.md` §2.
- Шалгасан: `TestQRFlow` (SessionID/DocumentNumber/Certificate), `TestForwardedClientIP`, `TestForwardedClientIPRateLimit`;
  `gofmt`, `go vet`, `go test ./...`, `GOOS=linux go build`.
- **Sign session-ий дутуу хэсгүүд (client-side PAdES)** — v0.2.1-д гарсан (PR #11 tag-гүй; v0.2.1 release-д
  орсон). Портал HASH sign (RAW_DIGEST_SIGNATURE, digest = 32 байт DTBS)-д олсон дутуу:
  - **Device-link sign:** `Sign.DeviceLinkByEtsi` / `DeviceLinkByDocument` (`POST /signature/device-link/{etsi|document}/…`)
    — `initialCallbackUrl`, `interactions`, `fileName`, `onBehalfOf`, RAW_DIGEST параметрүүд. `DeviceLinkSession.LinkInput`
    — auth/sign/cert холбоосын `BuildDeviceLink` оролтыг session-оос угсарна. `SignContext` (`NotificationSession.Sign`,
    `DeviceLinkSession.Sign`) — илгээсэн digest/hash/алгоритм/interactions/callback.
  - **Certificate-choice:** `Sign.CertificateChoiceByEtsi`, `Sign.CertificateChoiceDeviceLink` (зөвхөн QR — CA-ийн хүсэлт
    callback авдаггүй), `Validator.ValidateCertificateChoice` → `Signer{Certificate, DocumentNumber, CertChoiceSessionID}`.
  - **Signer-ээр зурах:** `Sign.DigestForSigner` (`/signature/notification/linked/{documentNumber}` +
    `linkedSessionID`, cert choice-гүй бол `/notification/document/…`), `Sign.DeviceLinkForSigner`
    (`/signature/device-link/document/…`). Олон утастай иргэнд etsi-ээр эхлүүлбэл өөр утас зурж CMS эвдэрдэг тул
    documentNumber-аар л. Анхдагч `sha256WithRSAEncryption` + SHA-256; digest-ийн уртыг хүсэлтээс өмнө шалгана.
  - **`ValidateSignOptions.ExpectedAlgorithm`** — хүссэн RSA алгоритмаас өөр хариу (ж: PKCS#1 хүссэнд rsassa-pss) →
    `*ValidationError`; CA-ийн хуучин threshold-ECDSA credential-ийн `ecdsa-with-SHA256`-ийг зөвхөн EC P-256 + SHA-256
    үед. **`ExpectedCertificate`** — certificate-choice-ийн гэрчилгээнээс өөрөөр зурсан бол татгалзана.
  - **`ExpiresAt`** — тухайн үед CA session start хариунд хугацаа буцаадаггүй байсан (`sessionID`/`vc`, device-link-д
    token/secret) тул
    sign / cert-choice session-д хүсэлтээс өмнөх цаг + `Config.SignSessionTTL` (анхдагч `DefaultSignSessionTTL` = 600с
    = CA `EID_SIGN_SESSION_TTL_SECONDS`; CA админ 60–1800с болгож болно). `SessionExpiry` туслах. v0.2.2-оос CA (!357) `expiresAt` буцаадаг
    болсон тул SDK түүнийг авна; энэ тооцоолол зөвхөн талбаргүй (хуучин) CA-д.
  - 5 шинэ зам `rpRoutes`-д (live `/.well-known/eid`-д бүгд бий).
  - Хаана: `sign.go`, `certchoice.go`, `validator.go` (precheck → `sessionDone` + `leafOf`), `devicelink.go`, `types.go`,
    `routes.go`, `client.go`, README §3.3.
- Шалгасан: `sign_gaps_test.go` (device-link body/зам/LinkInput байт-ижил, ExpiresAt, cert choice body түлхүүрүүд,
  ValidateCertificateChoice, DigestForSigner linked/document/device-link + буруу оролтод хүсэлт явахгүй,
  ExpectedAlgorithm/ExpectedCertificate). `gofmt`, `go vet ./...`, `go test -race ./...`, `go test -tags contract`
  (live discovery), `GOOS=linux GOARCH=amd64 go build ./...`.

## 0.2.0 — 2026-10-14

- **BREAKING (v0.2.0): `oidc` багц хасагдсан; «eID-ээр нэвтрэх» = `eidlogin.Handler` (net/http) RP-API дээр.** eID-ийн
  OIDC provider (`login.eidmongolia.mn`) хасагдсан (2026-10-14 шийдвэр) тул `oidc/` (client, contract тест) ба README
  §2 OIDC устсан — openid-configuration прод дээр 404 болж `contract` job улаан байсан. Оронд нь Smart-ID RP-үүдийн
  хэв маяг: `eidlogin.New(Config{Client, OnSuccess, CallbackURL, Store?, RateLimit?, ClientIP?, …})`, `/auth/eid/`
  дор mount — `start` (POST qr | push; GET `?mode=web2app` → 302 eID апп, буцах хөтчийн `retScheme`/`retPkg` hint
  UA-аас), `status` (PENDING + секунд тутмын QR / WAIT_CALLBACK / OK / FAILED / EXPIRED), `callback` (Web2App +
  `userChallengeVerifier`). Төлөв серверт (`Store`, анхдагч `NewMemoryStore`), хөтчид HttpOnly cookie
  (`<sessionId>.<binding>`); callback зөвхөн эхлүүлсэн хөтчид (login CSRF); JSON-only POST + `Sec-Fetch-Site`; push-д
  анхдагч 3/мин нэг дугаарт; иргэн (`Identity`) зөвхөн `ValidateAuth`-ийн дараа `OnSuccess`-д. Хариуны хэлбэр TS SDK
  0.14.0-ийн `createEidLogin`-тэй ижил (хөтчийн товч `<eid-login-button>`). `Client.RPName()` нэмэгдсэн.
- Хаана: `eidlogin/eidlogin.go`, `eidlogin/eidlogin_test.go`, `client.go`, `doc.go`, `README.md` §2, `.github/workflows/contract.yml`.
- Шалгасан: `eidlogin` тест — fake RP-API (httptest) БОДИТ ACSP_V2 RSA-PSS гарын үсэг буцааж, `Validator` жинхэнээр
  шалгана: QR / push / Web2App, cookie binding, cookie-гүй callback татгалзах, буруу verifier, хуурамч гарын үсэг,
  flowType зөрөх (relay), CSRF, rate limit, нэг удаагийн OnSuccess. `gofmt`, `go vet ./...`, `go test -race ./...`,
  `GOOS=linux GOARCH=amd64 go build ./...`, `go test -tags contract -run Contract ./...` (live) ногоон.

## 0.1.6 — 2026-10-14

- **OIDC: `mtls_endpoint_aliases` (RFC 8705 §5)** — v0.1.6. `login.` хост mTLS хийдэггүй тул `require_mtls`-тэй RP
  code солиход `login.eidmongolia.mn/oauth2/token` дээр `401 invalid_client` авдаг байв. CA !347 discovery-д
  `mtls_endpoint_aliases.token_endpoint` (`https://rp.eidmongolia.mn/oauth2/token`, RP client cert шаардана) нэмсэн.
  `oidc.Discovery.MTLSEndpointAliases map[string]string`; `oidc.Config.UseMTLSEndpointAliases` (анхдагч false) — true +
  alias байвал token хүсэлт alias руу; alias алга бол `TokenEndpoint` руу буцна; alias https биш бол
  `ErrDiscoveryFailed`. Client cert нь `Config.HTTPClient`-ийн Transport-оор (RP-API-тай ижил). README: «mTLS-тэй RP».
  Хаана: `oidc/oidc.go`, `oidc/oidc_test.go`. TS SDK 0.13.0-тай ижил.
- Шалгасан: `TestMTLSEndpointAliases` — флагтай → alias, флаггүй → `token_endpoint`, alias алга → fallback, `http://`
  alias → `discovery_failed` (token хүсэлт явахгүй). `gofmt`, `go vet ./...`, `go test -race ./...`,
  `GOOS=linux GOARCH=amd64 go build ./...`.

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
