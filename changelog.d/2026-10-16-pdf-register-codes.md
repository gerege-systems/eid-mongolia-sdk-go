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
