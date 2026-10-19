### Changed — `Appearance.Page` 0 = eID verify хуудас БИШ сүүлийн хуудас (golden v6)

- **Юу:** `page` 0 / байхгүй үед оролтын хуудсуудыг сүүлээс нь шалгаж, өмнөх revision-уудын нэмсэн eID verify хуудсуудыг
  алгасна (энэ Prepare-ийн нэмэх verify хуудас аль хэдийн тооцогддоггүйтэй адил). Verify хуудас = `/Annots`-д
  `/Subtype /Link`, `/A << /S /URI /URI (https://ca.eidmongolia.mn/verify/<docId>) >>` (энэ баримтын docId-тай байт-ижил)
  annotation-тай хуудас — бичвэрээр таахгүй; эргэлзээтэй (өөр docId, `/rev` дагавар) бол агуулгын хуудас. Тодорхой
  дугаар (1…N) хэвээр. `core.DefaultStampPage`. PLACEMENT_SPEC §1a, APPEARANCE_SPEC §1.
- **Яагаад:** портал хоёр дахь гарын үсэгт `page: 0` дамжуулдаг — тэмдэг эхний гарын үсгийн verify хуудсан дээр бууж
  байв (TS 0.25.0, «ТЕСТ гэрээ - eID Word-signed.pdf»: page 3 = verify).
- **Хаана:** `pades/prepare.go` (`visibleSpec`), `pades/internal/core/appearance.go`, spec-үүд; golden v6
  (`manifest.json` + 5 кейс, `input/two-verify.pdf`, `input/fake-verify.pdf`, `http/28…32`), `TestDefaultStampPage`.
- **Шалгасан:** `TestGolden -update` → v5-ийн 23 кейс, гаралт, HTTP fixture байт-ижил (зөвхөн нэмэгдсэн);
  `go test ./...` arm64 + `GOARCH=amd64`.
