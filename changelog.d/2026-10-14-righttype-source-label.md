- **`RightTypeLabel` / `SourceLabel`** (CA !344, additive) — `Representation.RightTypeLabel`, `Representation.SourceLabel`
  (`GetRepresentations`) ба session-ий `OrgResult.RightTypeLabel` (`OnBehalfOf`; тэнд `Source` байхгүй),
  `json:"…,omitempty"`. Эрхийн төрөл (ADMIN → «Админ» / Administrator, MANAGER → «Гарын үсэг зурагч» / Signatory) ба
  эх үүсвэрийн (REGISTRY → «Улсын бүртгэл» / State registry, MANUAL → «Захирал нэмсэн» / Added by the director) хүнд
  харуулах нэр, CA нэг газраас (`orgrole.RightTypeLabel` / `SourceLabel`, CA `docs/ORG_LOGIN.md` §4а); хэл нь
  `RoleLabel`-тэй ижил (`Config.Language` → `Accept-Language`). Клиент `RightType`/`Source` кодыг өөрөө орчуулахгүй.
  Хуучин CA-д хоосон. README: «RoleLabel / RightTypeLabel / SourceLabel». TS SDK 0.12.1-тэй ижил.
- Шалгасан: `TestRightTypeSourceLabel` (representations / session decode, хуучин хариунд хоосон, omitempty).
  `gofmt`, `go vet`, `go test -race`, `GOOS=linux go build`.
