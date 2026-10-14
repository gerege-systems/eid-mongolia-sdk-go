- **`ValidateSign(r, digest, hash, opts ...ValidateSignOptions)` — `ExpectedFlowType`** (additive: variadic, одоогийн
  дуудлагууд хэвээр хөрвөнө). Өгвөл хариуны `flowType` ЯГ таарах ёстой, эс бөгөөс `ValidateAuth`-тай ижил
  `*ValidationError` (`flowType X ≠ эхлүүлсэн урсгал Y (relay байж болзошгүй)`); нэгээс олон options → `*ValidationError`.
  Сонголтгүй / хоосон бол одоогийн зан. Яагаад: demo PDF device-link/push урсгалд flowType-ийг гараар тулгаж байсан
  (TS SDK 0.9.1-тэй ижил). RAW_DIGEST_SIGNATURE-д `flowType` гарын үсэгт ордоггүй — хариуны тулгалт.
- Шалгасан: `gofmt -l .`, `go vet ./...`, `go test -race ./...`.
