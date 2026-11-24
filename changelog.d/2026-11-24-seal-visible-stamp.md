### Changed — `pades.SealPDF`: харагдах байгууллагын тамганы дардас (анхдагч)

- **Юу:** `SealPDF` анхдагчаар баримтын сүүлийн (eID verify биш) хуудсанд байгууллагын **тамганы дардас** үлдээнэ:
  байгууллагын нэр, «eID Mongolia-аар тамгалсан» / «Sealed with eID Mongolia», тамгалсан цаг — QR, холбоос, үүрэггүй
  (`pades/APPEARANCE_SPEC.md` §6). Байршил: 220 × 64 pt, баруун доод булан (36 pt; жижиг хуудсанд багтаана, дардас
  багтахгүй бол үл харагдах тамга — `Completed.Placement` nil), агуулгатай давхцвал PLACEMENT_SPEC-ээр чөлөөт байрлал
  руу, чөлөөт газаргүй бол баруун доод буланд (`overlap`). Шинэ `SealOptions.Appearance`
  (байршлыг дуудагч өгнө, `Exact` ч), `SealOptions.Invisible`, `Completed.Placement`, тогтмолууд `SealStampWidth/Height/Margin`.
  Дардасны хувилбарыг ЗӨВХӨН гарын үсэг зурагчийн гэрчилгээ сонгоно (e-Seal гэрчилгээ: CA биш, keyUsage = nonRepudiation
  ба digitalSignature-гүй, EKU-гүй) — иргэний дардас өөрчлөгдөөгүй (golden v1–v11 байт-ижил). Validator (`ValidatePDF`,
  own-signer профайл) e-Seal гэрчилгээнд зөвхөн тамганы дардсыг, бусдад зөвхөн иргэний дардсыг хүлээн авна (таарахгүй бол
  өмнөх гарын үсэг `modified_after_signing`).
- **Зан өөрчлөлт (RP):** `SealPDF`-ийн анхдагч гаралт одоо ХАРАГДАНА. `SealOptions{Invisible: true}` өмнөх үл харагдах
  гаралтыг байт-ижил сэргээнэ.
- **Анхаар:** энэ хувилбараас ӨМНӨХ шалгагчид (CA `/v3/validate/pdf`, TS SDK `validatePdf`) тамганы дардсыг таньдаггүй тул
  түүний өмнөх бүх гарын үсгийг өөрчлөгдсөн гэж мэдээлнэ. CA ба TS SDK-ийн validator §6.3-ыг гаргахаас өмнө RP харагдах
  тамга ашиглахгүй (`Invisible: true`).
- **Release:** CA ба TS SDK-ийн validator §6.3-ыг гаргахаас өмнө энэ өөрчлөлтийг release/tag хийхгүй.
- **Хаана:** `pades/seal.go`, `pades/prepare.go`, `pades/complete.go`, `pades/internal/core/appearance.go`,
  `pades/internal/core/signature.go`, `pades/internal/validate/{appearance,extract}.go`; спец `APPEARANCE_SPEC.md` §6,
  `PLACEMENT_SPEC.md` §1, `PROFILE.md`; golden v12 (`testdata/golden` seal тохиолдлууд, `testdata/validate` 5 тохиолдол).
- **Шалгалт:** PR-ийн CI (go test -race; golden-external pyHanko/qpdf).
