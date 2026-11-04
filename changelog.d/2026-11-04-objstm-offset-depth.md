### Security — ObjStm-ийн бүхэл бус offset, `N G obj` гинж, xref offset-оор PDF задлагчийн `fatal error: stack overflow`

- **Юу:** `pades` (`Prepare`, `SuggestPlacement`, `Complete`, `Verify`, `ValidatePDF`) хуурамч PDF-д RP-ийн процессыг
  бүхэлд нь унагаж болдог байв (`fatal error: stack overflow` — recover барихгүй). v0.8.0–v0.22.0 бүгдэд. ~400 KB баримт
  хангалттай. (1) ObjStm-ийн толгойн offset бүхэл бус (`3 2.5`, `1e9`, `[`, `/N`, `(x)`, `true`) эсвэл сөрөг бол задлагч
  0 / `first+off`-оос уншдаг ч `CheckStructure` тэр хосыг алгасдаг байсан — `/First` дээрх гүн `[[[…` шалгагдахгүй.
  (2) Бүхэл offset-той ч `1 0 obj 1 0 obj …` гинжийг гүн гэж тоолдоггүй; xref-ийн offset шууд `[[[…` руу заасан баримтыг
  scanner хардаггүй. (3) `first+off` int64-ээс давахад `CheckStructure` сөрөг индексээр **panic** хийдэг байв —
  `Prepare`/`SuggestPlacement`-д recover байхгүй тул дуудагч goroutine унана.
- **Засвар:** `github.com/gerege-systems/pdf` v0.1.3 → **v0.1.4** (объектын давхарлалт > 1000 → задлалын алдаа, `PDF_INVALID`);
  `CheckStructure` ObjStm-ийн offset-ийг задлагчтай яг ижил тооцно (бүхэл бус → 0, сөрөг/wrap-тай `first+off`; `first+off < 0`
  → `PDF_INVALID`). **Шинэчлэх:** `go get github.com/gerege-systems/eid-mongolia-sdk-go@v0.22.1` — эсвэл ядаж
  `go get github.com/gerege-systems/pdf@v0.1.4` (Go MVS-ээр SDK-ийн хуучин хувилбарт ч задлагчийн засвар очно).
- **Хаана:** `go.mod`/`go.sum`, `pades/internal/validate/nesting.go`, `pades/PRECHECKS.md` (2a); тест
  `pades/internal/validate/objstm_offset_test.go`, `pades/objstm_offset_test.go`. CA !470-д ижил засвар.
- **Шалгасан:** локал PoC (дэд процесс) — өмнө нь 1 GB stack-тай in-process FATAL, одоо `PDF_INVALID`; шинэ тестүүд
  v0.1.3 / хуучин scanner дээр унадаг; `go test ./...`; `TestGolden -update` → golden diff хоосон; Extract replay
  683 PDF × 2 профайл main-тай байт-ижил; `FuzzValidatePDF` 60 s, `FuzzCheckStructure` 30 s; `go vet`, staticcheck,
  gofmt, linux/amd64 build, govulncheck (дуудагдсан олдворгүй); review (opus, xhigh) — blocking алга.
