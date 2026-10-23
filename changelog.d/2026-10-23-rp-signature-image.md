### Added — `Person.SignatureImage`, `Representation.StampImage` (RP-API зураг)

- **Юу:** `c.Person.SignatureImage(ctx, personEtsi)` → `GET /person/etsi/{personEtsi}/signature-image`
  (`*eid.Image{PNG, SHA256, Width, Height, UpdatedAt, PDFImage}`; 404 → `(nil, nil)`; 403 → `*ForbiddenError`).
  `Representation.StampImageSet`, `Representation.StampImage *eid.Image` (SIGN эрхтэй RP-д). `eid.PDFImage` — CA-ийн
  «PDF зураг»; `pades.PDFImage` нь одоо түүний alias (`type PDFImage = eid.PDFImage`, талбар/JSON хэвээр) тул
  `img.PDFImage`-ийг `pades.Appearance.SignatureImage` / `StampImage`-д шууд өгнө. Route гэрээнд
  (`rpRoutes`) нэмэгдэв.
- **Яагаад:** demo/портал зургийг SDK-гүйгээр гараар татаж байсан (SDK gap); CA docs/SIGNATURE_IMAGES.md-ийн хэлбэр.
- **Хаана:** `person.go`, `types.go`, `routes.go`, `pades/prepare.go`, `images_test.go`, README §3.6, §7.1.
- **Шалгасан:** `go test -race ./...` (stub: 200 задаргаа, 404 → nil, 403; representations stampImage), `go vet`,
  staticcheck, `GOOS=linux go build`, contract (live discovery-д `signature-image` зам бий).
