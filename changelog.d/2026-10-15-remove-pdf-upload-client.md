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
