### Security — pades: ObjStm `/N` нь stream-ээс их үед тасралтгүй скан

- **Юу:** PDF fork-ийг `github.com/craftzbay/pdf v0.1.3-eid.2` болгов: ObjStm-ийн `/N` нь stream-д байгаа объектоос их бол
  stream-ийн төгсгөлд зогсоно (өмнө нь `/N` удаа хоосон эргэж CPU зарцуулдаг байв). `pades` ашигладаг апп өөрийн
  `go.mod`-ийн `replace` мөрийг `v0.1.3-eid.2` болгоно (README «Суулгах»).
- **Хаана:** `go.mod`, `go.sum`, `README.md`, `pades/internal/validate/lexer_loop_test.go` (+1 кейс).
- **Шалгасан:** шинэ кейс eid.1 дээр гацаж унасан, eid.2 дээр хурдан; `go test ./...` ногоон.
