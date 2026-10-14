- **`RoleLabel`** (CA !339, additive) — `Representation.RoleLabel` (`GetRepresentations`) ба session-ий
  `OrgResult.RoleLabel` (`OnBehalfOf`), `json:"roleLabel,omitempty"`: албан тушаалын хүнд харуулах нэр, CA нэг газраас
  (`server/internal/orgrole`, CA `docs/ORG_LOGIN.md` §4а) өгнө. `Role` нь машин утга (`ceo` / `founder` / `stakeholder`
  эсвэл MANUAL текст) — клиент өөрөө орчуулахгүй, `RoleLabel`-ийг харуулна. Хуучин CA-д хоосон.
- **`Config.Language`** — дуудлага бүрд `Accept-Language` (`"mn"` | `"en"`); `""` = илгээхгүй (сервер mn). TS SDK
  0.12.0-ийн `language`-тэй ижил.
- Шалгасан: `TestRoleLabel` (representations / session decode, хуучин хариунд хоосон, omitempty), `TestLanguageHeader`
  ("" → header алга, "en", " mn " → "mn"). `gofmt`, `go vet`, `go test -race`, `GOOS=linux go build`,
  `go test -tags contract` (live).
