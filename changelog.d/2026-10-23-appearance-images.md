### Added — signature / organization-stamp images in the visible stamp (APPEARANCE_SPEC §6, golden v10)

- **Юу:** `pades.Appearance.SignatureImage`, `StampImage` (`*pades.PDFImage{Width, Height, Color, Alpha, SHA256}` — CA-ийн
  «PDF зураг»: нэг өнгө + 8 бит alpha, zlib-ийг SDK байтаар нь /SMask болгон бичнэ, runtime шахалт үгүй). Зураг widget-ийн
  `/AP /N` form дотор (A2: гарын үсэг дээд зурваст голлуулсан; B1: гарын үсэг зүүн тийш, тамга баруун дээд буланд
  хайрцгаас 29.5 pt дээш гарч бусдыг дарна). `Width = Height = 0` → анхдагч хэмжээ (220×64 / 220×110 / 240×147.5) Prepare
  ба `SuggestPlacement`-д. Validator зургийн объектуудыг PDF-ээс уншсан өнгө/хэмжээ/alpha-аар дахин үүсгэж байт-түвшинд
  тулгана. `Completed.Images` → `Registration` → `PDFSignatureRegistration.Images` (`images: [{kind, sha256}]`).
- **Яагаад:** тусдаа `/Stamp` annotation-ийг Adobe «Annotations Created», pyHanko `OTHER` гэж үздэг; form дотор бол
  өмнөх гарын үсэг «not modified» / `FORM_FILLING` хэвээр.
- **Хаана:** `pades/internal/core/appearance.go`, `core/signature.go`, `internal/validate/appearance.go`,
  `pades/prepare.go`, `suggest.go`, `state.go`, `complete.go`, `register.go`, `pdfregister.go`; spec
  APPEARANCE_SPEC §6, PLACEMENT_SPEC §6c, PROFILE §2; golden v10 (`img-*` 7 кейс, `http/48…52`).
- **Шалгасан:** `go test -race ./...` (v9-ийн бүх golden байт-ижил), validator халдлага 12 (`TestOwnVisibleSignatureImages`),
  оролтын шалгалт 12 (`TestAppearanceImageInput`), pyHanko 0.38 (62 гарын үсэг OK; `img-second` sig1 `FORM_FILLING`),
  qpdf (pikepdf 12.4) асуудалгүй, рендер: PDFKit, pdfium, pdf.js, MuPDF.
- **Үлдсэн:** CA `POST /v3/pdf/signatures` нь `images`-ийг хүлээн авах (DisallowUnknownFields — одоо 400; contract CI
  `TestContractPDFSignaturesBody` CA discovery-д `images?` нэмэгдтэл улаан); CA-ийн RP API «PDF зураг» хэлбэрээр өгөх;
  TS/.NET/Swift/Kotlin порт; Adobe гар шалгалт.
