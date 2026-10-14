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
