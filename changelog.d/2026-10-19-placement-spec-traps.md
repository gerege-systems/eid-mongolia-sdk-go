### Fixed — `pades` placement: saturating float → int (`SatInt`); PLACEMENT_SPEC port traps + 8 vectors

- **Юу:** `/W` CID, `/FirstChar`, quantise, `Round100`-ийн float → int нь `core.SatInt` (NaN → 0, хүрээнээс гарсан /
  ±Inf → MinInt64 / MaxInt64). PLACEMENT_SPEC: §2 saturating дүрэм; §3.1 zlib — тасархай (deflate эсвэл Adler-32 дутуу),
  буруу Adler-32 → unscannable, Adler-ийн дараах байт үл тоогдоно, FDICT DICTID = 1 зөвшөөрөгдөнө (бусад → unscannable),
  truncation илрүүлдэггүй decoder (.NET `ZLibStream`) дангаараа нийцгүй; §3.4 font cache = агуулж буй indirect объект
  (шууд бичигдсэн хоёр фонт нэг мөр). `placement/vectors.json`-д 8 vector: `zlib-trailing`, `zlib-truncated-data`,
  `zlib-no-adler`, `zlib-bad-adler`, `zlib-fdict-empty`, `zlib-fdict-other`, `fonts-direct`, `int-saturate`.
- **Яагаад:** Go-гийн `int(f)` хүрээнээс гарсан утгад платформоос хамаардаг — `/W [0 1e20 100]` arm64 дээр бүх CID-д
  100, amd64 дээр юу ч оноохгүй (`/DW` 1000) байсан тул эталон өөрөө Linux ба Mac дээр өөр box гаргадаг байв. Бусад
  заалтууд TS/.NET/native port-уудад гарсан зангууд.
- **Хаана:** `pades/internal/core/{occupancy.go,appearance.go,placement_test.go}`, `pades/PLACEMENT_SPEC.md`,
  `pades/testdata/golden/placement/{vectors.json,input/*.pdf}`.
- **Шалгасан:** `-update-placement` → өмнөх 21 vector байт-ижил, шинэ 8; `TestGolden -update` → golden v5 өөрчлөгдөөгүй;
  `go test ./pades/...` arm64 ба `GOARCH=amd64` (Rosetta) хоёуланд; `TestSatInt`.
