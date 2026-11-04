### Security — ObjStm-ийн zip bomb / гүний хамгаалалтыг тойрох гурван зам хаагдав

- **Юу:** `pades/internal/validate/nesting.go` (`CheckStructure`; `Prepare`, `ValidatePDF`, `Verify`, `Complete`,
  `SuggestPlacement` дууддаг) ба `pades/prepare.go` (`encrypted`) — санах ойн DoS; SDK RP-ийн процесс дотор
  хязгааргүй ажилладаг тул процесс OOM / `fatal error: stack overflow`-оор унах боломжтой. v0.8.0–v0.21.0 бүгдэд.
  1. `CheckStructure` шифрлэлтийг файлын БҮХ түүхий байтаас regex-ээр (`/Encrypt <<` / `/Encrypt N G R`) тодорхойлж,
     таарвал ObjStm-ийн бүх шалгалтыг (32 MiB zip bomb, `/DecodeParms`, лавлагаатай толгой, гүн) алгасдаг байв —
     `% /Encrypt <<` тайлбар, мөр эсвэл stream өгөгдөл хангалттай (~98 KB → 683 MiB).
  2. Scanner ба digitorus `/Filter`-ийг өөрөөр уншдаг байв: `[/FlateDecode /FlateDecode]` (digitorus гинжлэн
     задална), давхар түлхүүр `/Filter /FlateDecode /Filter null` эсвэл `[]` (digitorus сүүлийнхийг түүхийгээр уншина),
     массив доторх лавлагаа `/Filter [6 0 R]` (digitorus resolve хийж задална) — 1.6 KB → 1.69 GB, 507–545 байтаар
     stack overflow.
  3. `encrypted()` нь `/Encrypt`-ийг resolve хийдэг тул AES-128 (V4/AESV2)-д digitorus panic → recover → false болж
     `Prepare` / `SuggestPlacement` шифрлэгдсэн баримтыг `scanSignatures` руу оруулж, тайлсан ObjStm-ийг задалдаг байв
     (CheckStructure зөвхөн ciphertext-ийг харсан) — 262 KB → 1.69 GB.
- **Засвар:** (1) алгасалтыг бүрэн хасав — ObjStm-ийг шифрлэлтээс үл хамааран шалгана; жинхэнэ шифрлэгдсэн баримтын
  ciphertext zlib болж задрахгүй тул хуурамч татгалзалт үүсэхгүй. (2) `/Filter`-ийг digitorus шиг (давхар түлхүүрийн
  сүүлийнх, null / `[]` = түүхий) уншиж, 2+ шүүлтүүр / массив доторх лавлагааг `PDF_INVALID` (`ErrPDFStructure`) болгоно. (3) `encrypted()`
  `Trailer().Keys()`-ээр (resolve хийхгүй), panic бол түүхий байтын шалгалтаар. AES-128 баримтад `Prepare` /
  `SuggestPlacement` одоо `PDF_ENCRYPTED` (өмнө `PDF_INVALID`); шифрлэгдсэн ObjStm-ийн `/DecodeParms` / лавлагаатай
  толгой одоо `PDF_INVALID` (өмнө `PDF_ENCRYPTED`) — ховор, аль аль нь татгалзалт. API, golden гаралт өөрчлөгдөөгүй.
- **Хаана:** `pades/internal/validate/nesting.go`, `pades/prepare.go`; тест `pades/internal/validate/objstm_encrypt_test.go`
  (+ `FuzzCheckStructure`), `pades/encrypt_test.go`; fixture `pades/testdata/encrypted-objstm/` (qpdf 12.4.2
  `--object-streams=generate --encrypt`: AES-256, AES-128, RC4-128, шахаагүй RC4 ObjStm). CA-д (1)(2) ижил засвар.
- **Шалгасан:** шинэ тестүүд хуучин код дээр унасан, засвартай ногоон; шифрлэгдсэн 4 fixture `CheckStructure` nil,
  `ValidatePDF` / `Prepare` / `SuggestPlacement` → `PDF_ENCRYPTED`; `go test ./...` (golden өөрчлөлтгүй),
  `FuzzCheckStructure` 60 + 45 + 45 с, `FuzzValidatePDF` 60 с; gofmt, go vet, staticcheck, `GOOS=linux GOARCH=amd64 go build`,
  govulncheck. Бие даасан review (opus, xhigh) — 3 шат, review-ийн PoC засвартай `PDF_ENCRYPTED` / `PDF_INVALID`.
- **Анхаар:** `pades`-ийг `replace github.com/digitorus/pdf => github.com/craftzbay/pdf v0.1.3-eid.2`-гүй ашиглавал
  digitorus/pdf v0.1.2-ийн DoS засваргүй хэвээр (README «Суулгах»).
