### Security — pades: PDF lexer-ийн хаагдаагүй массив/мөр дээрх мөнхийн давталт

- **Юу:** `github.com/digitorus/pdf` v0.1.2-ийг `github.com/craftzbay/pdf v0.1.3-eid.1` (`replace`) fork-оор солив: массив
  дотор `endobj`, мөн ObjStm/контент stream-ийн төгсгөлд хаагдаагүй массив, hex мөр, literal мөр нь `PDF_INVALID`
  болно; ObjStm `/Extends` гогцоо зогсоно. Өмнө нь `Prepare`/`Verify`/`ValidatePDF` ийм оролт дээр буцахгүй, санах ой
  хязгааргүй өсдөг байв.
- **Анхаар:** Go хамаарлын `replace`-ийг дамжуулдаггүй — `pades` ашигладаг апп өөрийн `go.mod`-д ижил `replace` мөрийг
  нэмнэ (README «Суулгах»).
- **Хаана:** `go.mod`, `go.sum`, `README.md`; регресс тест `pades/internal/validate/lexer_loop_test.go`.
- **Шалгасан:** шинэ тест v0.1.2 дээр 3 кейс гацаж унасан, fork дээр бүгд хурдан `ErrNotPDF`; `go test ./...` ногоон,
  `go vet`, `GOOS=linux go build`.
