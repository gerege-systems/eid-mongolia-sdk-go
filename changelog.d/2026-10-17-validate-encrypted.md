### Fixed — `pades.ValidatePDF`: шифрлэгдсэн PDF → `PDF_ENCRYPTED` (v0.7.1)

- **Юу:** `/Encrypt`-тэй баримт (RC4, AES-128, AES-256; хоосон хэрэглэгчийн нууц үгтэй ч) одоо `PDF_ENCRYPTED`
  («шифрлэгдсэн PDF-ийг шалгах боломжгүй — нууцлалыг арилгаад дахин оролдоно уу») буцаана.
- **Яагаад:** digitorus/pdf хоосон нууц үгээр тайлахдаа RC4-д гарын үсгийн `/Contents`-ийг (спекээр шифрлэгддэггүй)
  эвдэж зөв гарын үсгийг `malformed_signature` (invalid) гэж буруу тайлагнадаг, AES-128-д panic → `PDF_INVALID`,
  AES-256 / нууц үгтэйд `PDF_INVALID` — шалтгааныг хэлдэггүй байв. TS SDK `validatePdf` (0.20.1) ба CA
  (`encrypted` код) ижил зан төлөвтэй болно.
- **Хаана:** `pades/internal/validate/extract.go` (`ErrEncrypted`; trailer `Keys()`-ээр — resolve хийхгүй; reader
  нээгдэхгүй бол `/Encrypt n g R`), `pades/validatepdf.go`, conformance `pades/testdata/validate/` (+4 тохиолдол:
  `encrypted-rc4-128`, `encrypted-aes-128`, `encrypted-aes-256`, `encrypted-user-password`).
- **Шалгасан:** `go test ./...`, `go vet ./...`; өмнөх зан төлөвийг (RC4 → invalid/malformed, AES → PDF_INVALID) ижил
  файлууд дээр v0.7.0-аар давтаж баталсан.
