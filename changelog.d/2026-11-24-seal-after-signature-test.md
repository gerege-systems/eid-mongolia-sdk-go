### Tests — иргэний гарын үсгийн дараа тамгалах (`TestSealPDFAfterCitizenSignature`)

- **Юу:** иргэний PIN2 гарын үсэгтэй (verify хуудас + DSS) PDF-ийг `SealPDF`-ээр тамгалах, мөн эсрэг дараалал (тамга →
  иргэн): хоёр гарын үсэг хоёулаа valid PAdES-BASELINE-LT (usage "sign" ба "seal"), хоёр дахь нь цэвэр incremental append
  (өмнөх файл яг угтвар).
- **Яагаад:** `TestSealPDF` зөвхөн гарын үсэггүй PDF-ийг тамгалдаг байсан — иргэний гарын үсэг тамгалалтаар эвдрэхгүйг
  батлах тест байгаагүй.
- **Хаана:** `pades/seal_test.go` (тест + `citizenSign` helper). Бүтээгдэхүүний код өөрчлөгдөөгүй.
- **Шалгалт:** PR-ийн CI (go test -race).
