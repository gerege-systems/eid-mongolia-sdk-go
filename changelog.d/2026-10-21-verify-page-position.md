### Added — `PrepareOptions.VerifyPagePosition` ("last" | "first"), golden v9

- **Юу:** баталгаажуулалтын (QR) хуудсыг баримтын ЭХЭНД (1-р хуудас) нэмэх сонголт: `VerifyPagePosition`
  (`VerifyPageLast` анхдагч / `VerifyPageFirst`, JSON `verifyPagePosition`). "first" үед хуудас үндсэн `/Pages`-ийн
  `/Kids`-ийн эхэнд орно (`core.InsertVerifyPage`); бусад бүх байт "last"-тай ижил. Үл мэдэгдэх утга → `REQUEST_INVALID`.
  `Appearance.Page`, `SuggestPlacement`, `Placement.Page` нь үргэлж ОРОЛТЫН баримтын хуудсаар (нэмэгдсэн хуудсыг
  тоолохгүй) — SDK дотроо +1 болгож зурна. Хуудас нэмэгдэхгүй үед (гарын үсэгтэй баримт, `VerifyPage` false) нөлөөгүй.
- **Яагаад:** хэрэглэгч гарын үсэгтэй баримтыг нээмэгц шалгах QR-ийг эхэнд харахыг хүссэн (портал/desktop-д сонголт).
- **Хаана:** `pades/prepare.go`, `pades/internal/core/vpage.go`, `pades/PAGE_SPEC.md` §8a, `pades/PLACEMENT_SPEC.md` §1b,
  `pades/verifypos_test.go`, golden v9 (`vpfirst-*` 8 кейс, `http/41…47`).
- **Шалгасан:** `TestVerifyPagePosition` (1-р хуудас = verify, widget оролтын хуудас+1 дээр, placement first = last,
  page > оролтын тоо → REQUEST_INVALID, буруу утга, хуудасгүй үед нөлөөгүй); `TestGolden -update` → v8-ийн бүх кейс/гаралт/
  HTTP байт-ижил (manifest-д зөвхөн нэмэгдсэн, 2 удаа ажиллуулахад ижил); `qpdf --check`; `ci/pyhanko_check.py` (56
  гарын үсэг OK); `go test ./...`; `GOOS=linux GOARCH=amd64 go build ./...`. TS/Swift/Kotlin-д урьдчилж ажиллуулахад
  vpfirst кейсүүд байт-ижил.
