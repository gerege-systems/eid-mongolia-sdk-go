### Tests — golden v8: verify page chain with non-zero object generations

- **Юу:** PLACEMENT_SPEC §1a-д «Object generations» дүрэм: `N G R` нь зөвхөн xref-ийн `G` generation-тэй бичлэгт
  шийдэгдэнэ; docId-ийн хайлт xref-ийг объектын дугаараар гүйж объект бүрийг **xref-д бичигдсэн generation**-оор уншина
  (0 гэж таамаглахгүй). Go reference аль хэдийн ингэдэг (`docIDFromPage` — `x.Ptr()`), кодын өөрчлөлтгүй.
- **Яагаад:** Swift SDK docId-ийг verify хуудасны Link-ээс generation 0-оор уншдаг байсан (Kotlin бодит generation) —
  gen ≠ 0 PDF дээр SDK-ууд өөр docId/хуудас сонгож байт-ижил гаралт эвдэрнэ.
- **Хаана:** `pades/PLACEMENT_SPEC.md` §1a; golden v8 — `input/verify-gen1.pdf` (verify хуудас `6 1 obj`, Link `7 1 obj`,
  URI action `8 2 obj`, revision 1-д free (next gen 1/1/2) — pyHanko strict xref; `pades/internal/core/placement_test.go` `verifyGen1Input`), кейс `verify-gen1`,
  `page0-verify-gen1`, `page-explicit-verify-gen1`, `http/38…40`.
- **Шалгасан:** `TestGolden -update` → v7-ийн бүх кейс/гаралт/HTTP fixture байт-ижил (manifest-д зөвхөн нэмэгдсэн);
  `page0-verify-gen1` docId = хуудаснаас, page 1; `page-explicit-verify-gen1` гаралт `6 1 obj`-ийг дахин бичсэн;
  `qpdf --check`, `ci/pyhanko_check.py` (47 гарын үсэг OK); `go test ./...`; `GOOS=linux GOARCH=amd64 go build ./...`.
