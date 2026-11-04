### Changed — PDF задлагч `github.com/gerege-systems/pdf` (`replace` хэрэггүй)

- **Юу:** `pades` нь `github.com/digitorus/pdf`-ийн оронд `github.com/gerege-systems/pdf v0.1.3`-ийг импортлоно —
  10-21-ний DoS засвартай fork (`craftzbay/pdf v0.1.3-eid.2`-той код нь байт-ижил), өөрийн module замтай. `go.mod`-оос
  `replace github.com/digitorus/pdf => github.com/craftzbay/pdf v0.1.3-eid.2` хасагдсан. **Танай `go.mod`-д README-ийн хуучин
  `replace` мөр байвал устгана уу** (v0.22.0-аас SDK `digitorus/pdf`-ийг импортлохгүй тул тэр мөр хэрэггүй).
- **Яагаад:** Go хамаарлын `replace`-ийг дамжуулдаггүй — README-ийн мөрийг хуулаагүй RP засваргүй digitorus/pdf v0.1.2
  (хаагдаагүй массив/мөр, ObjStm-ийн мөнхийн давталт) авч байв. Одоо засвар хүн бүрд автоматаар очно. Upstream v0.3.0 руу
  шилжээгүй: ObjStm-ийн filter гинжээр zip-bomb хамгаалалтыг тойрдог, объектын кэш нь том PDF-д heap-ийг 41 → 435 MiB болгодог.
- **Хаана:** `go.mod`/`go.sum`; `pades/*.go`, `pades/internal/{core,validate}/*.go`-ийн импорт; README «Суулгах». pdfsign-ээр
  (зөвхөн тестэд) гарын үсэг зурдаг 4 тест файл upstream `digitorus/pdf`-ийн `*pdf.Reader`-ийг pdfsign-д өгсөөр — production
  код (`go list -deps ./...`) зөвхөн `gerege-systems/pdf`.
- **Шалгасан:** `go test ./...`; `TestGolden -update` → `pades/testdata/golden` `git diff` хоосон (40 гаралт байт-ижил); main-тай
  харьцуулсан Extract replay 515 PDF × 2 профайл (1030 мөр) ижил; pdfsig 40/40 valid, qpdf алдаагүй, `openssl cms` 56 CMS;
  `go vet`, staticcheck, gofmt, linux/amd64 build, govulncheck (шинэ олдворгүй); `replace`-гүй хэрэглэгч module build.
