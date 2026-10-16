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
