- **PAdES: харагдах гарын үсэг (сонголттой) + golden v3 + гадны шалгалт (qpdf, pyHanko).**
  - Юу: `PrepareOptions.Appearance` (`page`, `x`, `y`, `width`, `height`, `lang`) — nil бол үл харагдах, v2 golden байт-ижил.
    Харагдах widget `/Rect` (CropBox-ийн харагдах эх, `/Rotate` 0/90/180/270), `/F 4`, `/P`, хуудасны `/Annots`-д
    (incremental), `/AP /N` form XObject (шахалтгүй, verify хуудасны фонт, өөрийн QR): нэр, үүрэг, «eID Mongolia-аар
    зурсан» / «Signed with eID Mongolia», огноо (+08), QR `https://ca.eidmongolia.mn/verify/<docID>/<revIndex>`.
    Дүрэм: `pades/APPEARANCE_SPEC.md` (хэмжээ/тойруулга/wrap/жижгэрэх, багтахгүй → `REQUEST_INVALID`, §5 validator).
  - Validator (own-signer): зөвхөн яг энэ widget + 11 /AP объектыг дахин үүсгэж байт-түвшинд тулгаж хүлээн авна; ObjStm
    доторх хуудсыг шууд объектоор дахин бичихийг (own, page/annots) зөвшөөрнө. Тайланд `visible` талбар.
  - DSS: давхардалгүй байдлыг (ижил DER → нэг stream, массивт нэг удаа; өмнөх DSS-ийн объектыг дахин ашиглах) PROFILE.md §7-д
    тодорхой бичиж, golden бүрд тест (`dssUnique`) — бичигч аль хэдийн ингэж ажилладаг тул гаралт өөрчлөгдөөгүй.
  - CI: `golden-external` job — golden гаралт бүрд `qpdf --check` ба pyHanko (INTACT/VALID/TRUSTED, DSS-ээс LT, timestamp,
    өөрчлөлтийн түвшин, харагдах).
- Хаана: `pades/prepare.go`, `pades/internal/core/{appearance,signature,vpage}.go`, `pades/internal/validate/{appearance,
  revisions,extract,validate}.go`, `pades/internal/padestest`, `pades/{APPEARANCE_SPEC,PROFILE}.md`, `pades/testdata/golden`
  (manifest + 5 тохиолдол, `input/quartz-rotated90.pdf`, `ci/pyhanko_check.py`), `.github/workflows/ci.yml`, README.
- Шалгасан: `TestGolden` (v2 тохиолдлын гаралт өөрчлөгдөөгүй — git diff), `TestOwnVisibleSignature` (хүлээн авах + 17
  халдлага), `TestAppearanceRejects`, `TestVisibleRect`, `TestNum100`; pdfsig (Signature is Valid), qpdf --check,
  pyHanko 0.37 (19 гарын үсэг OK), pdftoppm/PDFKit render, QR-ийг CIDetector-оор уншсан; gofmt, vet, `go test -race ./...`,
  linux build.
- Үлдсэн: CA `server/internal/validate`-д §5-ийг порт (тусдаа агент); native SDK-ууд (TS/Swift/Kotlin/.NET) v3 golden;
  PDFKit (macOS) `/Rotate`-тэй хуудсан дээрх widget-ийг зурдаггүй (poppler зурна) — шалгах.
