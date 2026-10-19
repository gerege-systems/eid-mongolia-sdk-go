### Security — `pades`: цуцлалтын нотолгооны тохирол/шинэлэг байдал, revoked = хатуу алдаа, гүн давхарласан PDF (v0.7.2)

- **Юу (зан төлөвийн өөрчлөлт — аюулгүй байдлын засвар):**
  - `ValidatePDF` / `Verify` (DSS ба онлайн): OCSP нь ЭНЭ гэрчилгээнийх байх ёстой — CertID = гинжийн олгогчийн
    нэр/түлхүүрийн hash + serial (өмнө нь зөвхөн serial, аль ч eID олгогчийн гарын үсэгтэй хариу тооцогддог байв). CRL нь
    гэрчилгээний олгогчийнх (нэр = олгогчийн subject, AKI = SKI, гарын үсэг) — өмнө нь өөр eID олгогчийн (05) serial-ийг
    агуулаагүй CRL «good» болдог байв. «good» нотолгоо шалгах цагт (цагийн тэмдгийн цаг, эс бөгөөс `Time`/одоо) шинэлэг
    байх ёстой: thisUpdate ≤ одоо+5 мин, nextUpdate ≥ шалгах цаг−5 мин, thisUpdate ≥ шалгах цаг−24 ц эсвэл
    thisUpdate…nextUpdate нь шалгах цагийг хамарна (`validate.FreshAt`, `RevocationMaxAge`, `RevocationClockSkew`) — өмнө
    нь DSS-ийн 400 хоногийн өмнөх OCSP `valid` өгдөг байв. Олгогчийн гарын үсэгтэй «revoked» (OCSP/CRL, онлайн/DSS) нь
    «good»-ийг үргэлж давна (өмнө нь DSS-д good OCSP + revoked CRL → `valid`; онлайн good нь DSS-ийн revoked-ийг дардаг байв).
    **Өмнө `valid` байсан зарим баримт одоо `indeterminate` (`revocation_unavailable`) эсвэл `invalid` (`revoked`).**
  - `Complete`: OCSP «revoked» эсвэл гэрчилгээг агуулсан CRL → тэр дор нь `LTV_UNAVAILABLE` + `errors.Is(err,
    pades.ErrCertificateRevoked)`, дахин оролдохгүй (өмнө нь revoked OCSP-г алгасаад CRL-ээр DSS угсарч амжилттай
    дуусдаг байв). OCSP/CRL-д мөн CertID/олгогч/шинэлэг байдлын дүрэм.
  - `Prepare` / `ValidatePDF` / `Verify` / `Complete`: задлахын өмнө массив/толийн давхарлалт > 256 → `PDF_INVALID`
    (`Complete` — `STATE_INVALID`), `errors.Is(err, pades.ErrPDFStructure)` — өмнө нь ~2 MB `[[[…` баримт digitorus/pdf-ийн
    рекурсээр `fatal error: stack overflow` (recover барихгүй) өгч процессыг унагадаг байв.
- **Шинэ API (нэмэлт):** `pades.ErrCertificateRevoked`, `pades.ErrPDFStructure`.
- **Яагаад:** 10-15 SDK аудитын олдвор 1–5 (fail-open цуцлалт, crash).
- **Хаана:** `pades/internal/validate/revocation.go` (FreshAt, OCSPCertIDMatches, CRLFor), `nesting.go` (CheckStructure),
  `validate.go` (StatusSource-д cert/issuer/цаг), `ltv.go`; `pades/trust.go` (dssStatus), `pades/validatepdf.go`
  (onlineStatus), `pades/ltv.go` (collectLTV), `pades/complete.go`, `pades/prepare.go`, `pades/errors.go`; README §7.2,
  PRECHECKS.md #2a. Golden **v4** (`pades/testdata/validate/`, +13: `dss-ocsp-stale`, `-expired`, `-future`,
  `-other-serial`, `-other-issuer`, `-revoked`, `-revoked-after-signing`, `dss-crl-revoked`, `-wrong-issuer`, `-only`,
  `dss-no-revocation`, `deep-nesting`, `deep-nesting-objstm`; `issuers`-д тестийн `pki/05.pem`); v3 тохиолдлууд байт-ижил.
- **Шалгасан:** `go test -race ./...`, `go vet`, gofmt, `GOOS=linux GOARCH=amd64 go build`, staticcheck (шинэ анхааруулга
  алга), govulncheck (0). Шинэ тестүүдийг v0.7.1-ийн код дээр ажиллуулж унахыг баталсан: golden v4-ийн 8 тохиолдол
  (stale/expired/future/other-issuer/crl-revoked/crl-wrong-issuer → `valid`, deep-nesting* → `PDF_NO_SIGNATURE`),
  `TestValidatePDFOnlineRevocationEvidence` (3 дэд), `TestCompleteRevokedIsHardFailure` (2 дэд — хуучин нь амжилттай);
  3 MB давхарлалт хуучин кодонд `fatal error: stack overflow`.
- **Үлдсэн:** TS/Swift/Kotlin/.NET port-ууд golden v4-ийг давтах; CA-ийн `validate` хуулбарт ижил дүрэм (LTV хамралтын
  CertID/CRL/шинэлэг байдал).
