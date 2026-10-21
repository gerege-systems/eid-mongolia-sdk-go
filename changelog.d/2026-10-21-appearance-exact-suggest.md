### Added — `Appearance.Exact` + `pades.SuggestPlacement` (golden v7)

- **Юу:** `Appearance.Exact` (json `exact`) — иргэний өөрөө сонгосон байрлал: тэмдгийг хэзээ ч шилжүүлэхгүй, яг
  `Page/X/Y/Width/Height`-д зурна; хуудаснаас гарвал `REQUEST_INVALID`; хуудсыг уншиж `Placement.Status` = `requested`
  | `overlap` (агуулгатай давхцвал) | `unscanned`. `pades.SuggestPlacement(pdf, Appearance) (Suggestion, error)` — Prepare-ийн
  байршлын алгоритмыг гарын үсэггүй ажиллуулж шийдэгдсэн хуудас, байрлал, статус, тухайн хуудасны ба бүх хуудасны
  харагдах хэмжээ (`Pages[]`), `PageCount`-ийг буцаана. `Exact: false` (анхдагч) өмнөхтэй байт-ижил.
- **Яагаад:** портал ба eid-desktop иргэнд PDF-ийг урьдчилан харуулж тэмдгийг хаана тавихыг өөрөө сонгуулна — хэрэглэгчийн
  сонгосон байрлалыг авто-шилжүүлэх нь буруу; UI анхдагч байрлал, хуудасны хэмжээг SDK-аас авах хэрэгтэй.
- **Хаана:** `pades/prepare.go`, `pades/suggest.go`, `pades/internal/core/{placement,suggest,signature,appearance}.go`;
  PLACEMENT_SPEC §6a/§6b/§8, APPEARANCE_SPEC §1, README §7.1; golden v7 (`manifest.json`: visible кейс бүрд
  `expect.suggestion`, 5 шинэ кейс, `http/33`, `http/35…37`).
- **Шалгасан:** `TestGolden -update` → v6-ийн бүх кейс, гаралт, HTTP fixture байт-ижил (manifest-д зөвхөн нэмэгдсэн);
  `exact-free` / `exact-page0-after-verify`-ийн `preparedSha256` = `table-bottom-visible` / `page0-after-verify`;
  кейс бүрд SuggestPlacement = Prepared.Placement (`page0-two-verify`-ээс бусад, §6b); `TestSuggestPlacementErrors`;
  `go test ./...` arm64 + `GOARCH=amd64`; `GOOS=linux GOARCH=amd64 go build ./...`.
