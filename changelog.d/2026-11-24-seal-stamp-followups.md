### Fixed — харагдах дардасны validator: урт /Name-ийг эрт татгалзана; мөр таслалт хязгаартай

- **Юу:**
  - `ValidatePDF` (own-signer, харагдах widget — `ownVisible`): Sig толийн `/Name` нь `ownTextLimit`-ээс (256 байт) урт
    бол дардсыг дахин үүсгэхээс өмнө татгалзана. Дүгнэлт өөрчлөгдөөгүй (`sigValue` ийм нэрийг аль хэдийн татгалздаг —
    эхний гарын үсэг `modified_after_signing`); олон мегабайт `/Name` квадрат мөр таслалтыг ажиллуулахаа больсон (TS SDK
    0.48.0-ийн засвартай ижил).
  - `wrapLimit` (дардас/verify хуудасны мөр таслалт): `maxLines`-аас илүү мөр гармагц цааш мөр үүсгэхгүй — гаралт
    байт-ижил (golden өөрчлөгдөөгүй).
  - Үг хэллэг: e-Seal гэрчилгээний EKU нөхцөл = «EKU-ийн зорилго байхгүй (extendedKeyUsage алга эсвэл хоосон)» —
    `APPEARANCE_SPEC.md` §6.1, `eid.IsSealCertificate`, `sealCertificate`-ийн тайлбар, README (код өөрчлөгдөөгүй).
- **Яагаад:** v0.30.0-ийн review-ийн дагалдах засвар.
- **Хаана:** `pades/internal/validate/appearance.go`, `pades/internal/core/vpage.go`, `pades/APPEARANCE_SPEC.md`,
  `seal.go`, `README.md`; тест `pades/internal/validate/appearance_test.go` (`/Name 256 байтаас урт`).
- **Шалгалт:** PR-ийн CI (go test -race, golden — нэг ч golden/testdata өөрчлөгдөөгүй).
