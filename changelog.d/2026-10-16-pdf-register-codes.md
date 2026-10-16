### Нэмэгдсэн

- **`POST /pdf/signatures`-ийн `Code*` тогтмолууд ба `PDFRegisterErrorCodes`** — CA main `pades_register.go`,
  `handlers_pdf.go` (2026-10-16)-ийн бүх код: `CodeRequestTooLarge`, `CodeCMSInvalid`, `CodeSignatureInvalid`,
  `CodeTimestampInvalid`, `CodeSignerMismatch`, `CodeSignerCertInvalid`, `CodeTokenCertInvalid`, `CodeTokenOrgMismatch`,
  `CodeSessionMismatch`, `CodeSessionNotComplete`, `CodeSessionFailed`, `CodeClaimedRoleMismatch`, `CodeDocIDConflict`,
  `CodeRegistryConflict`, `CodeDocNotFound`, `CodePriorMismatch` (+ одоо байгаа `CodeRequestInvalid`,
  `CodeRepresentationRevoked`, `CodeRateLimited`, `CodeStateUnavailable`). Яагаад: TS SDK 0.18.3-ийн
  `PDF_REGISTER_ERROR_CODES`-тэй нийцүүлэх (contract журам). Хаана: `pdfregister.go`.

Шалгасан: `go vet ./...`, `go test ./...` (шинэ `TestPDFRegisterErrorCodes`), `GOOS=linux GOARCH=amd64 go build ./...`.
