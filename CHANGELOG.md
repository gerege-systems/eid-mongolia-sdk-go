# Changelog

## v0.17.0 — 2026-10-23

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

## v0.16.0 — 2026-10-23

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
- **`eid.CodeImageMismatch` (`IMAGE_MISMATCH`, 409)** `PDFRegisterErrorCodes`-д (`CodePriorMismatch`-ийн ард) — CA
  `images`-ийг одоогийн хадгалсан зурагтай тулгана (CA прод f604ed2b; discovery `registerErrorCodes`).
- **alpha FDICT** — FLG-ийн FDICT бит тавигдсан alpha (DICTID = 1 ч) `REQUEST_INVALID` (`compress/zlib` DICTID 1-ийг
  зөвшөөрдөг байсан — спектэй зөрж байв; тест `alpha FDICT 1`).
- **TestGolden зургийг manifest-ээс авна** (`-update`-ээс бусад үед) — `compress/zlib`-ийн гаралт Go 1.27-д өөрчлөгдсөн тул
  `testImage`-ээс дахин шахсан alpha v10-ийн байттай зөрж байв (CI `test (stable)`); Go 1.26.4 ба 1.27.3 дээр ногоон.
- **Үлдсэн:** Adobe гар шалгалт.

## v0.15.2 — 2026-10-21

### Security — pades: ObjStm `/N` нь stream-ээс их үед тасралтгүй скан

- **Юу:** PDF fork-ийг `github.com/craftzbay/pdf v0.1.3-eid.2` болгов: ObjStm-ийн `/N` нь stream-д байгаа объектоос их бол
  stream-ийн төгсгөлд зогсоно (өмнө нь `/N` удаа хоосон эргэж CPU зарцуулдаг байв). `pades` ашигладаг апп өөрийн
  `go.mod`-ийн `replace` мөрийг `v0.1.3-eid.2` болгоно (README «Суулгах»).
- **Хаана:** `go.mod`, `go.sum`, `README.md`, `pades/internal/validate/lexer_loop_test.go` (+1 кейс).
- **Шалгасан:** шинэ кейс eid.1 дээр гацаж унасан, eid.2 дээр хурдан; `go test ./...` ногоон.

## v0.15.1 — 2026-10-21

### Security — pades: PDF lexer-ийн хаагдаагүй массив/мөр дээрх мөнхийн давталт

- **Юу:** `github.com/digitorus/pdf` v0.1.2-ийг `github.com/craftzbay/pdf v0.1.3-eid.1` (`replace`) fork-оор солив: массив
  дотор `endobj`, мөн ObjStm/контент stream-ийн төгсгөлд хаагдаагүй массив, hex мөр, literal мөр нь `PDF_INVALID`
  болно; ObjStm `/Extends` гогцоо зогсоно. Өмнө нь `Prepare`/`Verify`/`ValidatePDF` ийм оролт дээр буцахгүй, санах ой
  хязгааргүй өсдөг байв.
- **Анхаар:** Go хамаарлын `replace`-ийг дамжуулдаггүй — `pades` ашигладаг апп өөрийн `go.mod`-д ижил `replace` мөрийг
  нэмнэ (README «Суулгах»).
- **Хаана:** `go.mod`, `go.sum`, `README.md`; регресс тест `pades/internal/validate/lexer_loop_test.go`.
- **Шалгасан:** шинэ тест v0.1.2 дээр 3 кейс гацаж унасан, fork дээр бүгд хурдан `ErrNotPDF`; `go test ./...` ногоон,
  `go vet`, `GOOS=linux go build`.

## v0.15.0 — 2026-10-21

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

### Added — `PrepareOptions.VerifyPagePosition` ("last" | "first"), golden v9

- **Юу:** баталгаажуулалтын (QR) хуудсыг баримтын ЭХЭНД (1-р хуудас) нэмэх сонголт: `VerifyPagePosition`
  (`VerifyPageLast` анхдагч / `VerifyPageFirst`, JSON `verifyPagePosition`). "first" үед хуудас үндсэн `/Pages`-ийн
  `/Kids`-ийн эхэнд орно (`core.InsertVerifyPage`); бусад бүх байт "last"-тай ижил. Үл мэдэгдэх утга → `REQUEST_INVALID`.
  `Appearance.Page`, `SuggestPlacement`, `Placement.Page` нь үргэлж ОРОЛТЫН баримтын хуудсаар (нэмэгдсэн хуудсыг
  тоолохгүй) — SDK дотроо +1 болгож зурна. Хуудас нэмэгдэхгүй үед (гарын үсэгтэй баримт, `VerifyPage` false) нөлөөгүй.
- **Яагаад:** хэрэглэгч гарын үсэгтэй баримтыг нээмэгц шалгах QR-ийг эхэнд харахыг хүссэн (портал/desktop-д сонголт).
- **Хаана:** `pades/prepare.go`, `pades/internal/core/vpage.go`, `pades/PAGE_SPEC.md` §8a, `pades/PLACEMENT_SPEC.md` §1b,
  `pades/verifypos_test.go`, golden v9 (`vpfirst-*` 8 кейс, `http/41…47`).
- **Шалгасан:** `TestVerifyPagePosition` (1-р хуудас = verify, widget оролтын хуудас+1 дээр, placement first = last,
  page > оролтын тоо → REQUEST_INVALID, буруу утга, хуудасгүй үед нөлөөгүй); `TestGolden -update` → v8-ийн бүх кейс/гаралт/
  HTTP байт-ижил (manifest-д зөвхөн нэмэгдсэн, 2 удаа ажиллуулахад ижил); `qpdf --check`; `ci/pyhanko_check.py` (56
  гарын үсэг OK); `go test ./...`; `GOOS=linux GOARCH=amd64 go build ./...`. TS/Swift/Kotlin-д урьдчилж ажиллуулахад
  vpfirst кейсүүд байт-ижил.

## v0.14.0 — 2026-10-21

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

## v0.13.1 — 2026-10-20

### Docs — CA !403 (b040b463) нийцэл

- **Юу:** токен олголт / dryRun — RP-д зөвхөн `TOKEN_ISSUE` эрх (SIGN биш); `ACCOUNT_DELETE_PENDING` эхлэл ба preview-д
  push-ээс өмнө 409 (өмнө зөвхөн үр дүнгийн шатанд) — token start/preview-ийн алдааны жагсаалтад нэмэв; `claimedRole`
  mn ба en хоёуланг CA хүлээн авна; RP нэр ≤ 120 **тэмдэгт** (байт биш, CA тэмдэгтээр таслана).
- **Яагаад:** CA !403 прод дээр (`ca.eidmongolia.mn`) — бодлого өөрчлөгдсөн. Кодын зан өөрчлөгдөөгүй (SDK-д discovery
  `registration` блокийн төрөл байхгүй тул `registration.paused` нэмэх зүйлгүй).
- **Шалгасан:** CA `origin/main` b040b463-ийн `tokencert.go`, `store.go` (`displayNameMaxRunes`), `pades_register.go`.

## v0.13.0 — 2026-10-20

### Fixed — SDK аудитын кодын алдаанууд (TS / .NET / Swift / Kotlin-той нийцүүлэв)

**Юу ба яагаад.**
- `Session.WaitForResult` 150 с-т таслахаа болив (CA auth 300 с, sign 600 с — иргэн 150 с-ээс хойш баталбал RUNNING
  буцаж validator унадаг байв). `MaxWait` өгөөгүй бол: `WaitOptions.ExpiresAt` (шинэ; start хариуны `ExpiresAt`) +
  `WaitGrace` (15 с) → discovery `sessionTtl` (max(auth, sign)) + 15 с → `DefaultMaxWait` (150 → **600 с**). `MaxWait`
  өгвөл түүнийг л дагана; long-poll хэвээр. Хугацаа өнгөрсөн `ExpiresAt`-д ч нэг poll хийнэ (CA-ийн TIMEOUT-ийг авна).
- Токены кодын тогтмолууд: `CodeTokenIssuancePending`, `CodeKYCIncomplete`, `CodeNoActiveDevice`, `CodeCSRKeyReused`,
  `CodeCSRInvalid`, `CodeCSRKeyUnsupported`, `CodeCSRSignatureInvalid`, `CodeCSRKeysIdentical`, `CodeIssuanceFailed`,
  `CodeResultExpired`, session-ий `CodeCSRDigestMismatch` / `CodeSignerCertChanged` / `CodeIssuanceError` /
  `CodeRegistryFailed`, токеноор нэвтрэлтийн `CodeRPRequired` / `CodeChallengeExpired` / `CodeChallengeUsed` /
  `CodeCertInvalid` / `CodeCertNotActive`; бүгдийг `TokenErrorCodes`-д (CA `tokencert.go`, `token_auth.go`).
- `pades.Complete`: RSASSA-PSS гарын үсэг → `SIGNATURE_INVALID` (өмнө `REQUEST_INVALID`; бусад 4 SDK, CA-ийн бүртгэлийн
  кодтой ижил). Мессеж («PKCS#1 v1.5 шаардлагатай») хэвээр.
- `pades.Registration`: `Medium` "" бол `SessionID`-аас (phone ⇔ sessionID — CA-ийн дүрэм; өмнө хоосноор илгээгдэж
  CA 400 буцаадаг байв); phone + SessionID "" / token + SessionID / үл мэдэгдэх medium → `REQUEST_INVALID`.
- `pades.Completed.ClaimedRole` (шинэ); `Registration` нь claimedRole-той гарын үсэгт `OnBehalfOf` хоосон бол
  `REQUEST_INVALID` (өмнө CA дараа нь татгалздаг байв).
- `TokenService` godoc: олголтод зөвхөн `TOKEN_ISSUE` эрх («TOKEN_ISSUE + SIGN» биш).

**Хаана.** `session.go`, `auth.go` (`fetchSessionTTL`), `token.go`, `pades/complete.go`, `pades/register.go`, README.

**Хэрхэн шалгасан.** `TestWaitDeadline` (discovery / ExpiresAt / өнгөрсөн ExpiresAt / MaxWait / хуучин CA / 503),
`TestSession_PollAndWait`, `TestRegistrationAndPSS`, `TestRegistrationMediumAndRole`; `gofmt -l`, `go vet ./...`,
`go test ./...`, `GOOS=linux go build ./...`.
### Docs — README/godoc ↔ код ↔ CA аудит (зөвхөн баримт)

**Юу.** README-ийн жишээ, хязгаар, алдааны код, godoc-ийг v0.12.0-ийн код, CA (`origin/main`), амьд `/.well-known/eid`,
`/mobile/app-config`-той тулгаж зөрүүг засав. Кодын зан өөрчлөгдөөгүй.

- `go get …@v0.4.0` → `@v0.12.0` (v0.4.0-д Share/ValidatePDF/PreviewCertificate байхгүй тул жишээ хөрвөхгүй байв).
- Share квот цагт 300 / өдөрт 3000 (өмнө 30/200); `ShareInfo.Enabled` туг биш — 503 `MAIL_UNAVAILABLE`/`VALIDATOR_UNAVAILABLE`.
- §4 алхам 1: `State != COMPLETE` → `*ValidationError`, `EndResult != OK` → `*SessionFailedError`.
- §7.1 `Page 0` = eID verify хуудас БИШ сүүлийн хуудас (v0.12.0, PLACEMENT_SPEC §1a); golden tag `pades-golden-v6` (v4 tag байхгүй).
- `Complete`-ийн давхарлалтын алдаа `STATE_INVALID`; ValidatePDF жишээнд `CodeRequestInvalid`; `RPName` ≤ 120 **байт**.
- Товчны CDN `@0.26.0` (0.15.4-д 429/503 Retry-After тоолуур байхгүй); status `PENDING`-ийн `vc`/`expiresIn`;
  аппын доод хувилбар iOS ≥ 2.2.8 / Android ≥ 91 (10-20); §3.7/§3.8 дараалал; English хэсгийн хамаарал.
- §3.2 / §3.7 жишээний `:=` давхар зарлалт засав (токены жишээ: оролт → preview → issue → result дараалал).
- godoc: `ShareInfo.Enabled`, share.go толгой, `Client` (Share/ShareInfo нь method), `ValidateCertificateChoice`
  (`SkipKeyUsageCheck`), `NationalRootCAPEM` (завсрын CA суусан), `Credentials.RPName`, `pades` package жишээ (`ValidatePDF`).

**Хэрхэн шалгасан.** README-ийн ```go блок бүрийг typed stub-тай боож `go build -gcflags=-e` (v0.12.0 replace) — үлдсэн нь
§3.4-ийн өмнөх хэсгээс `signer`/`dtbs` авдаг fragment л; `gofmt -l`, `go vet ./...`, `go test ./...`.

**Үлдсэн (код — энэ PR-д биш).** `WaitForResult` `DefaultMaxWait` 150 с < CA sign TTL 600 с; `CodeTokenIssuancePending`
тогтмол алга. CHANGELOG.md-ийн v0.11.0 «`signature.go` (`Visible.Avoid`)» (→ `appearance.go`) нэгтгэлийн үед засна.

## v0.12.0 — 2026-10-19

### Changed — `Appearance.Page` 0 = eID verify хуудас БИШ сүүлийн хуудас (golden v6)

- **Юу:** `page` 0 / байхгүй үед оролтын хуудсуудыг сүүлээс нь шалгаж, өмнөх revision-уудын нэмсэн eID verify хуудсуудыг
  алгасна (энэ Prepare-ийн нэмэх verify хуудас аль хэдийн тооцогддоггүйтэй адил). Verify хуудас = `/Annots`-д
  `/Subtype /Link`, `/A << /S /URI /URI (https://ca.eidmongolia.mn/verify/<docId>) >>` (энэ баримтын docId-тай байт-ижил)
  annotation-тай хуудас — бичвэрээр таахгүй; эргэлзээтэй (өөр docId, `/rev` дагавар) бол агуулгын хуудас. Тодорхой
  дугаар (1…N) хэвээр. `core.DefaultStampPage`. PLACEMENT_SPEC §1a, APPEARANCE_SPEC §1.
- **Яагаад:** портал хоёр дахь гарын үсэгт `page: 0` дамжуулдаг — тэмдэг эхний гарын үсгийн verify хуудсан дээр бууж
  байв (TS 0.25.0, «ТЕСТ гэрээ - eID Word-signed.pdf»: page 3 = verify).
- **Хаана:** `pades/prepare.go` (`visibleSpec`), `pades/internal/core/appearance.go`, spec-үүд; golden v6
  (`manifest.json` + 5 кейс, `input/two-verify.pdf`, `input/fake-verify.pdf`, `http/28…32`), `TestDefaultStampPage`.
- **Шалгасан:** `TestGolden -update` → v5-ийн 23 кейс, гаралт, HTTP fixture байт-ижил (зөвхөн нэмэгдсэн);
  `go test ./...` arm64 + `GOARCH=amd64`.

## v0.11.0 — 2026-10-19

### Changed — `pades`: the visible stamp avoids existing page content (PLACEMENT_SPEC.md)

- **What:** `Appearance.X/Y` is now the preferred spot. Before writing the widget, the target page is scanned
  (content stream text/paths/images/forms/inline images + annotation `/Rect`s, no rendering, no font files) and, when
  the requested rect (+4 pt) overlaps something, the stamp moves to the first free candidate: mirrored column at the
  same height (bottom-right → bottom-left), then up the requested column in 12 pt steps, then up the mirrored column.
  Nothing free → requested spot. New `Prepared.Placement` (`page, x, y, width, height, status`:
  `requested | moved | overlap | unscanned`).
- **Why:** prod 2026-10-19 — on a LibreOffice-converted Word contract the stamp covered the last-page footer.
- **Where:** `pades/internal/core/occupancy.go` (scanner), `placement.go` (candidates), `signature.go`
  (`Visible.Avoid`, `Prepared.Placement`), `pades/prepare.go`, spec `pades/PLACEMENT_SPEC.md`, APPEARANCE_SPEC §1,
  README §7.1. Golden v5: 6 new cases (`libreoffice-contract-visible`, `…-second`, `table-bottom-visible`,
  `rotated90-footer-visible`, `quartz-pdf13-visible-third`, `full-page-visible`), `expect.placement` on all visible
  cases; scanner vectors `pades/testdata/golden/placement/`. CI fuzz job also runs `FuzzOccupancy`.
- **Verified:** all v3/v4 golden outputs byte-identical (only `expect.placement: requested` added to the manifest);
  `go test -race ./...`, `go vet`, `gofmt`, staticcheck, govulncheck, `FuzzOccupancy` 60 s locally; before/after
  renders with pdftoppm.
- **Remaining:** TS / Swift / Kotlin / .NET ports (byte-identical to golden v5) and the `pades-golden-v5` tag at
  release.
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

## v0.10.0 — 2026-10-19

### Changed — `eidlogin`: хугацаа CA-ийн session-оос урт байхгүй; `Auth.SessionTTL` (discovery `sessionTtl`)

- **Юу:** `c.Auth.SessionTTL(ctx)` — discovery `/.well-known/eid`-ийн `sessionTtl` (`Auth`, `Sign`; хуучин CA-д 0).
  `eidlogin`: start-ийн `expiresIn`, cookie `Max-Age`, store-ийн хугацаа = QR/Web2App-д min(`Config.TTL`, CA-ийн
  `expiresAt` − одоо); push-д (бодит ба decoy ижил) min(`Config.TTL`, discovery `sessionTtl.auth`, 10 мин кэш). Хуучин
  CA-д бодит push-ийн `expiresAt`-аас ажигласан утгыг decoy авна. `Config.TTL`-ийн анхдагч (2 мин) хэвээр.
- **Яагаад:** RP `TTL`-ийг CA-ийнхаас урт тохируулбал иргэн CA дууссан session-ийг хүлээж үлддэг; decoy-д CA хариу
  байхгүй тул CA-ийн `expiresAt`-аар таслах нь бодит/decoy push-ийн хугацааг ялгаж (бүртгэлтэй эсэхийн oracle) болох байв.
- **Хаана:** `auth.go` (`SessionTTL`), `eidlogin/eidlogin.go` (`authTTL`, `observeAuthTTL`, `begin`/`save`/`startDecoy`),
  README (eidlogin §хугацаа, `ExpiresAt`), `portal_gaps_test.go` (`TestAuthSessionTTL`), `eidlogin/security_test.go`
  (`TestPushTTLFromDiscovery`, `TestPushTTLObservedWithoutDiscovery`, `TestQRTTLCappedByCAExpiresAt`).
- **Шалгасан:** `gofmt`, `go vet`, `go test ./...` (eidlogin 3 удаа), `GOOS=linux go build`.
- **Үлдсэн:** CA discovery-д `sessionTtl` (CA MR) deploy болтол push нь ажигласан утгаар (±1 с) ажиллана.
### Added — `TokenCertInput.AppTransaction`, `CodeAppAttestationInvalid`

- **Юу:** `POST /token/certificate`-д заавал биш `appTransaction` (StoreKit 2 AppTransaction JWS, ≤ 16 KiB;
  `json:"appTransaction,omitempty"`). `MaxAppTransactionBytes`-аас их бол илгээхгүй — `ErrAppTransactionTooLarge`.
  400 `CodeAppAttestationInvalid` (`APP_ATTESTATION_INVALID`) тогтмол. Discovery `TokenCertInfo.AppTransaction`
  (`"optional"`; хуучин CA-д `""`).
- **Яагаад:** CA (MR !390) macOS App Store build-ийн апп баталгааг токены олголтод нэмсэн; SDK-ийн хүсэлтийн бүтэц
  талбаргүй байсан тул портал дамжуулж чадахгүй байв.
- **Хаана:** `token.go`, README §3.7, `portal_gaps_test.go` (`TestTokenCertificateAppTransaction`,
  `TestTokenCertificateInfo`), `contract_test.go` (`TestContractTokenCertificate` — `appTransaction: "optional"`).
- **Шалгасан:** `gofmt`, `go vet`, `go test ./...`, `go test -tags contract -run ContractTokenCertificate` (live
  discovery), `GOOS=linux go build`.
### Added — `Token.PreviewCertificate` (dryRun), `TokenCertInfo.DryRun`

- **Юу:** `c.Token.PreviewCertificate(ctx, in)` — `POST /token/certificate` ижил бие + `"dryRun": true` →
  `*TokenCertPreview{Supersedes}`; алдаа `IssueCertificate`-тэй ижил (`*APIError`, `TokenLimitOf` …); хариунд
  `dryRun: true` алга бол `*ValidationError`. Оролтын шалгалт/бие угсралт нэг `certRequest`-д. Discovery `TokenCertInfo.DryRun`.
- **Яагаад:** `Supersedes` бодит эхлэлийн хариунд ирэх үед PIN2 push явсан байдаг; RP push-ээс өмнө иргэнд анхааруулах
  хэрэгтэй (CA MR feat/token-cert-dryrun).
- **Хаана:** `token.go`, README §3.7, `portal_gaps_test.go` (`TestTokenCertificatePreview`), `contract_test.go`
  (live discovery-д `tokenCertificate.dryRun: true` — CA d3e071f7 прод).
- **Шалгасан:** `gofmt`, `go vet`, `go test ./...`, contract тест live discovery-д.
### Added — `TokenCertStart.Supersedes`, `TokenCertInfo.PersonalAutoSupersede`

- **Юу:** `IssueCertificate`-ийн хариунд `Supersedes []TokenSupersede{TokenSerial}` — хувийн хязгаар хүрсэн үед олголт
  амжилттай болоход superseded (4)-оор цуцлагдах өмнөх хувийн токенууд (бусад үед nil). Discovery
  `TokenCertInfo.PersonalAutoSupersede` (хуучин CA-д false). 409 `TOKEN_LIMIT_REACHED` `kind=PERSONAL` одоо зөвхөн `limit=0`.
- **Яагаад:** CA !392 (прод b09b755e) хувийн токены автомат солилт; RP PIN2-оос өмнө иргэнд анхааруулах ёстой.
- **Хаана:** `token.go`, README §3.7, `portal_gaps_test.go`, `contract_test.go` (`personalAutoSupersede: true`).
- **Шалгасан:** `gofmt`, `go vet`, `go test ./...`, contract тест live discovery-д.

## v0.9.0 — 2026-10-19

### Added — `PersonCertificate.TokenSerial`

- **Юу:** `c.Person.Certificates`-ийн `KeyMedium == "TOKEN"` мөрөнд гэрчилгээ олгогдсон USB токены серийн дугаар
  (`json:"tokenSerial,omitempty"`; CA `GET /v3/certificates/etsi/{personEtsi}`, 2026-10-19). MOBILE/HSM болон хуучин CA-д `""`.
- **Яагаад:** нэг токены AUTH + SIGN-ийг байгууллага + олгосон цагаар таамаглахгүй, токеноор нь бүлэглэх.
- **Хаана:** `person.go`, README §3.6, `share_test.go` (`TestPersonCertificateTokenSerial`).
- **Шалгасан:** `gofmt`, `go vet`, `go test ./...`.

## v0.8.0 — 2026-10-19

### Fixed — `pades`: trailer-ийн шууд `/Encrypt << … >>` толь `PDF_ENCRYPTED`

- **Юу:** digitorus баримтыг нээж чадахгүй үед (ж: AES-256, буруу /U) хэрэглэдэг байт-regex нь зөвхөн `/Encrypt N G R`
  лавлагааг таньдаг байсан тул шууд толь (`/Encrypt << … >>`, `/Encrypt<<`)-той баримт `PDF_INVALID` болдог байв —
  одоо `PDF_ENCRYPTED`. Regex `/Encrypt(?:\s+\d+\s+\d+\s+R|\s*<<)` (CA !382-тэй ижил); `/EncryptMetadata` тооцогдохгүй.
- **Хаана:** `pades/prepare.go` (`encryptKey`), `pades/internal/validate/extract.go` (`encryptRef`), `pades/PRECHECKS.md` #4.
- **Шалгасан:** `TestEncryptDirectDict` (AES-256 шууд толь, RC4 `/Encrypt<<`, лавлагаа, `/EncryptMetadata` → encrypted
  биш) — хуучин regex-ээр AES-256/RC4 тохиолдол унахыг баталсан.
### Tests — PRECHECKS #2b: хууль ёсны ObjStm баримтын хуурамч татгалзлын хамгаалалт

- **Юу:** `pades/testdata/objstm/` (qpdf 12.4.2 `--object-streams=generate`): Chrome 155 «Save as PDF» гаралт,
  linearized + ObjStm, гарын үсэгтэй хоёр (pdfcpu stamp, macOS-ийн eID гарын үсэгтэй баримт; бүтнээр дахин бичсэн тул
  зөвхөн бүтцийн шалгалтад). `TestObjStmLegitAccepted` — эдгээр ба `golden/input/{quartz,desktop}-objstm.pdf`-д
  `CheckStructure` зөвшөөрнө; гарын үсэггүйд `ValidatePDF` → `PDF_NO_SIGNATURE`, `Prepare` амжилттай. Шинэ файлууд
  `FuzzValidatePDF`-ийн seed болно.
- **Яагаад:** #2b-ийн ObjStm мөчлөгийн дүрэм бодит ObjStm-тэй баримтыг татгалзахгүйг батлах.
- **Шалгасан:** 6 файл бүгд ObjStm агуулагчийн шалгалтын замаар явсныг (түр `len(containers) > 0 → ErrStructure`
  болгоход 6 бүгд унасан) баталсан; дүрэм өөрчлөгдөөгүй; fuzz 2.5 мин олдворгүй.
### Security — `pades`: цуцлалтын нотолгооны тохирол/шинэлэг байдал, revoked = хатуу алдаа, гүн давхарласан PDF (v0.7.2)

- **Юу (зан төлөвийн өөрчлөлт — аюулгүй байдлын засвар):**
  - `ValidatePDF` / `Verify` (DSS ба онлайн): OCSP нь ЭНЭ гэрчилгээнийх байх ёстой — CertID = гинжийн олгогчийн
    нэр/түлхүүрийн hash + serial (өмнө нь зөвхөн serial, аль ч eID олгогчийн гарын үсэгтэй хариу тооцогддог байв). CRL нь
    гэрчилгээний олгогчийнх (нэр = олгогчийн subject, AKI = SKI, гарын үсэг) — өмнө нь өөр eID олгогчийн (05) serial-ийг
    агуулаагүй CRL «good» болдог байв. «good» нотолгоо шалгах цагт (цагийн тэмдгийн цаг, эс бөгөөс `Time`/одоо) шинэлэг
    байх ёстой: thisUpdate ≤ одоо+5 мин, nextUpdate ≥ шалгах цаг−5 мин, thisUpdate ≥ шалгах цаг−24 ц эсвэл
    thisUpdate…nextUpdate нь шалгах цагийг хамарна (`validate.FreshAt`, `RevocationMaxAge`, `RevocationClockSkew`) — өмнө
    нь DSS-ийн 400 хоногийн өмнөх OCSP `valid` өгдөг байв. Олгогчийн гарын үсэгтэй «revoked» (OCSP/CRL, онлайн/DSS) нь
    «good»-ийг үргэлж давна (өмнө нь DSS-д good OCSP + revoked CRL → `valid`; онлайн good нь DSS-ийн revoked-ийг дардаг байв).
    **Өмнө `valid` байсан зарим баримт одоо `indeterminate` (`revocation_unavailable`) эсвэл `invalid` (`revoked`).**
  - `Complete`: OCSP «revoked» эсвэл гэрчилгээг агуулсан CRL → тэр дор нь `LTV_UNAVAILABLE` + `errors.Is(err,
    pades.ErrCertificateRevoked)`, дахин оролдохгүй (өмнө нь revoked OCSP-г алгасаад CRL-ээр DSS угсарч амжилттай
    дуусдаг байв). OCSP/CRL-д мөн CertID/олгогч/шинэлэг байдлын дүрэм.
  - `Prepare` / `ValidatePDF` / `Verify` / `Complete`: задлахын өмнө массив/толийн давхарлалт > 256 → `PDF_INVALID`
    (`Complete` — `STATE_INVALID`), `errors.Is(err, pades.ErrPDFStructure)` — өмнө нь ~2 MB `[[[…` баримт digitorus/pdf-ийн
    рекурсээр `fatal error: stack overflow` (recover барихгүй) өгч процессыг унагадаг байв.
- **Шинэ API (нэмэлт):** `pades.ErrCertificateRevoked`, `pades.ErrPDFStructure`.
- **Яагаад:** 10-15 SDK аудитын олдвор 1–5 (fail-open цуцлалт, crash).
- **Хаана:** `pades/internal/validate/revocation.go` (FreshAt, OCSPCertIDMatches, CRLFor), `nesting.go` (CheckStructure),
  `validate.go` (StatusSource-д cert/issuer/цаг), `ltv.go`; `pades/trust.go` (dssStatus), `pades/validatepdf.go`
  (onlineStatus), `pades/ltv.go` (collectLTV), `pades/complete.go`, `pades/prepare.go`, `pades/errors.go`; README §7.2,
  PRECHECKS.md #2a. Golden **v4** (`pades/testdata/validate/`, +13: `dss-ocsp-stale`, `-expired`, `-future`,
  `-other-serial`, `-other-issuer`, `-revoked`, `-revoked-after-signing`, `dss-crl-revoked`, `-wrong-issuer`, `-only`,
  `dss-no-revocation`, `deep-nesting`, `deep-nesting-objstm`; `issuers`-д тестийн `pki/05.pem`); v3 тохиолдлууд байт-ижил.
- **Шалгасан:** `go test -race ./...`, `go vet`, gofmt, `GOOS=linux GOARCH=amd64 go build`, staticcheck (шинэ анхааруулга
  алга), govulncheck (0). Шинэ тестүүдийг v0.7.1-ийн код дээр ажиллуулж унахыг баталсан: golden v4-ийн 8 тохиолдол
  (stale/expired/future/other-issuer/crl-revoked/crl-wrong-issuer → `valid`, deep-nesting* → `PDF_NO_SIGNATURE`),
  `TestValidatePDFOnlineRevocationEvidence` (3 дэд), `TestCompleteRevokedIsHardFailure` (2 дэд — хуучин нь амжилттай);
  3 MB давхарлалт хуучин кодонд `fatal error: stack overflow`.
- **Үлдсэн:** TS/Swift/Kotlin/.NET port-ууд golden v4-ийг давтах; CA-ийн `validate` хуулбарт ижил дүрэм (LTV хамралтын
  CertID/CRL/шинэлэг байдал).
### Security — `pades`: ObjStm мөчлөг ба /Size-аар процесс унах / гацах (fuzz олсон)

- **Юу:** `validate.CheckStructure` (Prepare / ValidatePDF / Verify / Complete-ийн урьдчилсан шалгалт) нь дараахыг
  `PDF_INVALID` (`Complete` — `STATE_INVALID`), `errors.Is(err, pades.ErrPDFStructure)` болгоно:
  - ObjStm доторх объектын агуулагч stream нь өөрөө ObjStm-д (өөрийгөө агуулах эсвэл харилцан мөчлөг);
  - ObjStm-ийн толгойн лавлагаа (`/Length` г.м.) ObjStm доторх объект руу заасан; `/Extends` мөчлөг / > 64 гинж;
  - trailer эсвэл xref stream-ийн `/Size` > 2 097 152.
  Өмнө нь ~8 KB баримт digitorus/pdf-ийн мөчлөгийн рекурсээр `fatal error: stack overflow` (recover барихгүй, процесс
  бүхэлдээ унана), `/Size 10000000000` — хязгааргүй давталт (Linux-д 400 GB хуваарилалт) өгдөг байв.
- **Яагаад:** `FuzzValidatePDF` эхний 4 секундэд олсон; v0.7.2-ийн давхарлалтын засвартай ижил ангиллын DoS.
- **Хаана:** `pades/internal/validate/objstm.go` (`checkObjStmGraph` — digitorus-ийн экспортлоогүй xref талбарыг
  reflect-ээр уншина; бүтэц өөрчлөгдвөл fail-closed), `nesting.go` (`/Size`), `pades/PRECHECKS.md` #2b.
- **Шалгасан:** `TestCheckStructureObjStmGraph` (хууль ёсны ObjStm + /Size = хязгаар задарна; 4 муу тохиолдол) — шалгалтыг
  түр унтраахад self / mutual / /Length тохиолдлууд `fatal error: stack overflow`, /Size 10^10 30 с timeout өгснийг
  баталсан; fuzz crash `pades/testdata/fuzz/FuzzValidatePDF/c8b2f6dc9d5d37bf` regression seed; `TestCheckStructureCorpus`
  (хуурамч татгалзалгүй).
- **Үлдсэн:** TS/Swift/Kotlin/.NET port-ууд PRECHECKS #2b-г давтах (задлагч нь мөчлөгт хамгаалалттай бол код л тааруулна).
### Changed — 10-15 SDK аудитын Low олдворууд: PII-гүй алдаа, https BaseURL, CI-ийн staticcheck/govulncheck/fuzz, devicelink golden drift

- **Юу:**
  - `maskPath` нь `/linked/{documentNumber}`-ийг ч нууна (`/signature/notification/linked/…`) — өмнө нь баримтын
    дугаар `NetworkError.Op` / `ResponseTooLargeError` / алдааны текстэд орж болдог байв.
  - `pades.Complete`-ийн LTV/цуцлалтын алдааны текст иргэний гэрчилгээний CN (овог, нэр)-ийн оронд `serial <hex>`-ээр
    заана (`pades/ltv.go` `certRef`).
  - **Зан төлөвийн өөрчлөлт:** `ResolveBaseURL` / `NewClient` нь `http://`-ийг зөвхөн `localhost` / loopback IP
    (127.0.0.0/8, ::1)-д зөвшөөрнө; бусад `http://` → алдаа (API secret сүлжээгээр нээлттэй явахгүй).
  - CI: `lint` job (`staticcheck@v0.8.2`, `govulncheck@v1.8.0`, Go stable) ба `fuzz` job (`FuzzValidatePDF`, 30 с).
    staticcheck-ийн өмнөх 9 олдвор засагдсан (ашиглагдаагүй талбар, `t.Fatal(fmt.Sprintf)`, deprecated
    `timestamp.CreateResponse` → `CreateResponseWithOpts(…, crypto.SHA256)` (байт-ижил), тестийн U+202E/U+200E →
    escape, `Catalog` алдааны мөрөнд `//lint:ignore ST1005`).
  - `testdata/devicelink_golden.json`-ийн sha256-ийг pin хийсэн (`TestDeviceLinkGoldenPinned`); `EID_CA_REPO` (CA
    репогийн локал clone) өгвөл canonical файлтай байт-ижил эсэхийг мөн шалгана (CA репо private тул CI-д алгасна).
  - `FuzzValidatePDF` (`pades/fuzz_test.go`): ValidatePDF (offline) + Verify; seed = репогийн бүх тестийн PDF + олдсон
    crash (`pades/testdata/fuzz/`). Seed-үүд энгийн `go test`-д ажиллана.
- **Яагаад:** 10-15 SDK аудитын Low олдворууд.
- **Хаана:** `errors.go`, `client.go`, `pades/ltv.go`, `.github/workflows/ci.yml`, `devicelink_test.go`,
  `pades/fuzz_test.go`; тест: `TestMaskPathAllRoutes`, `TestResolveBaseURL`, `TestCompleteRevokedIsHardFailure` /
  `TestCollectLTVRejectsForeignEvidence` (`noSubjectCN`), `TestDeviceLinkGoldenPinned`.
- **Шалгасан:** gofmt, `go vet`, `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build`, staticcheck v0.8.2 (0),
  govulncheck v1.8.0 Go 1.27.2-оор (0 дуудагдах эмзэг байдал), fuzz нийт ~10 мин (засварын дараа олдворгүй).

## v0.7.1 — 2026-10-17

### Fixed — `pades.ValidatePDF`: шифрлэгдсэн PDF → `PDF_ENCRYPTED` (v0.7.1)

- **Юу:** `/Encrypt`-тэй баримт (RC4, AES-128, AES-256; хоосон хэрэглэгчийн нууц үгтэй ч) одоо `PDF_ENCRYPTED`
  («шифрлэгдсэн PDF-ийг шалгах боломжгүй — нууцлалыг арилгаад дахин оролдоно уу») буцаана.
- **Яагаад:** digitorus/pdf хоосон нууц үгээр тайлахдаа RC4-д гарын үсгийн `/Contents`-ийг (спекээр шифрлэгддэггүй)
  эвдэж зөв гарын үсгийг `malformed_signature` (invalid) гэж буруу тайлагнадаг, AES-128-д panic → `PDF_INVALID`,
  AES-256 / нууц үгтэйд `PDF_INVALID` — шалтгааныг хэлдэггүй байв. TS SDK `validatePdf` (0.20.1) ба CA
  (`encrypted` код) ижил зан төлөвтэй болно.
- **Хаана:** `pades/internal/validate/extract.go` (`ErrEncrypted`; trailer `Keys()`-ээр — resolve хийхгүй; reader
  нээгдэхгүй бол `/Encrypt n g R`), `pades/validatepdf.go`, conformance `pades/testdata/validate/` (+4 тохиолдол:
  `encrypted-rc4-128`, `encrypted-aes-128`, `encrypted-aes-256`, `encrypted-user-password`).
- **Шалгасан:** `go test ./...`, `go vet ./...`; өмнөх зан төлөвийг (RC4 → invalid/malformed, AES → PDF_INVALID) ижил
  файлууд дээр v0.7.0-аар давтаж баталсан.

## v0.7.0 — 2026-10-17

### Нэмэгдсэн — `pades.ValidatePDF` (v0.7.0)

- **Юу:** `pades.ValidatePDF(ctx, pdf, ValidateOptions)` — RP өөрийн backend дээр гарын үсэгтэй PDF-ийг CA-ийн нийтийн
  шалгагчийн (`/v3/validate/pdf`) кодоор шалгана, ижил JSON тайлан. Онлайн цуцлалт (AIA OCSP → CDP CRL → DSS fallback,
  `Offline` сонголт), `certificate_level` (eid.CertificateLevelOf), `key_medium` (CA !377; SDK-д гэрчилгээнээс: phone|unknown).
  Шинэ код `PDF_NO_SIGNATURE`; `PDF_TOO_MANY_SIGNATURES` (16-аас их). `Verify` нь `ValidatePDF`+Offline (deprecated, хуучин зан).
- **Засвар:** DSS-ийн OCSP-д олгогч өөрөө зурж өөрийн cert-ээ шигтгэсэн хариуг (RFC 6960 §4.2.2.2) хүлээн авна (v0.6.0
  NewOCSPChecker-тэй ижил).
- **Бусад (CA !377):** `CodeAccountDeletePending` (токен олголтын 409 `ACCOUNT_DELETE_PENDING`); contract тест
  `pdfSigning.registerErrorCodes`-ийг заавал тулгана; `PKICertificate.RevokedAt` SUPERSEDED мөрд ч ирнэ (doc).
- **Яагаад:** хэрэглэгчийн шийдвэр 10-16 — PDF-ийг хөтөч (TS `validatePdf`) ба RP backend (Go) дээр серверт илгээлгүй шалгана.
- **Хаана:** `pades/validatepdf.go`, `pades/verify.go`, `pades/trust.go`, `pades/internal/validate` (CertificateLevel,
  KeyMedium талбар, `CorpusHook` — зөвхөн тест), `pades/testdata/validate/` (conformance багц), `token.go`, `person.go`.
- **Шалгасан:** `go test ./...` (ValidateGolden 25 тохиолдол: зөв B-LT, objstm/linearized, олон revision, харагдах,
  tampered, modified-after-signing, untrusted, QUALIFIED/ADVANCED, онлайн good/revoked/revoked-after/CRL/хариугүй, хуучин
  stamp, гарын үсэггүй, PDF биш); TS SDK 0.20.0 ижил багцыг deep-equal давтана; differential corpus (Go тестийн 121 PDF)
  дээр TS extract 163/163, revisions 161/161, тайлан 121/121 ижил.
- **DN формат бэхэлсэн:** тайлангийн `certificate.subject/issuer` нь Go ≤1.26-ийн `pkix.Name.String()` хэлбэр (CA прод
  golang:1.26.9) — Go 1.27 танихгүй атрибутыг «#hex»-ийн оронд бичвэрээр гаргадаг болсон тул toolchain-аар өөрчлөгдөхгүй
  (`internal/validate/dn.go`; Go 1.25 ба 1.27-д тест ногоон).

## v0.6.0 — 2026-10-16

### ⚠️ BREAKING — аюулгүй анхдагч (SDK Багц 2, TS 0.19.0-тэй 1:1)

- **Гэрчилгээний зориулалт анхдагчаар шалгагдана** (өмнө `CheckKeyUsage: false` анхдагч). Нэвтрэлтийн (PIN1,
  P-CITIZEN-AUTH) түлхүүрийн гарын үсэг `ValidateSign`-д тэнцдэг байсан (AUTH гэрчилгээнд EKU emailProtection бий тул
  `x509.Verify`-аар өнгөрдөг байв) — одоо KU nonRepudiation алга гэж татгалзана. Унтраах: `SkipKeyUsageCheck: true`
  (шинэ, зөвлөхгүй); `CheckKeyUsage` — deprecated, нөлөөгүй (эвдэхгүйн тулд үлдсэн).
- **`AllowedIssuerSKIs` анхдагч `[]string{CitizenIssuingCASKI}`** (TrustAnchorsPEM тохируулсан үед). Ижил root-ийн
  доорх өөр CA (байгууллагын 05 г.м.)-ийн гэрчилгээ иргэнийх гэж тэнцэхгүй. Унтраах: `AllowAnyIssuer: true` (шинэ);
  жагсаалт өгвөл түүгээр шалгана.
- **Түвшин гэрчилгээнээс** (`CertificateLevelOf`, шинэ): SIGN-д qcStatements QcCompliance → QUALIFIED (+ QcSSCD → QSCD),
  qcStatements-гүй → ADVANCED; AUTH-д (CA qcStatements бичдэггүй) KeyUsage keyEncipherment (утасны профайл) →
  QUALIFIED, үгүй (токен) → ADVANCED. Хариуны утга гэрчилгээнийхээс өндөр бол `*ValidationError`, бага бол хариуных.
  `VerifiedIdentity` / `VerifiedSignature` / `Signer`-ийн `CertificateLevel` = энэ утга. Хариунд түвшин алга бол
  гэрчилгээнийх (өмнө татгалздаг байв).
- **`Token.AuthVerify(ctx, ch *TokenAuthChallenge, certDER, signature)`** — эхний аргумент challenge (өмнө
  `challengeID string`). SDK CA-ийн OK-д дангаар итгэхгүй: `ch.RPUUID` = энэ RP, r||s нь
  `TokenAuthDigest(RPUUID, Challenge)` дээр гэрчилгээний түлхүүрээр таарах, гэрчилгээ `Config.Trust`-аар (хугацаа,
  KU/EKU auth, гинж, issuer) хүчинтэйг CA руу илгээхээс өмнө шалгана.
- **`eidlogin`: `start` анхдагч хязгаар** нэг IP-ээс 60 с-д 20 (`DefaultRateLimit()["start"]`; `ClientIP` өгсөн бол).
  Унтраах: `RateLimits: map[string]RateRule{"start": {}}`.

### Засвар / нэмэлт

- `eidlogin` санах ойн хязгаарлагч: 10 000 түлхүүрээс хэтэрвэл map-ийг бүхэлд нь цэвэрлэдэг байсныг (10k өөр түлхүүрээр
  дүүргэж тухайн дугаарын push хязгаарыг тойрох боломжтой байв, `eidlogin.go` windowLimiter) — цонх нь өнгөрсөнийг
  цэвэрлээд, дүүрэн хэвээр бол шинэ түлхүүрийг татгалзана.
- `eidlogin.NewMemoryStore()` ≤ `MemoryStoreMax` (10 000): дүүрвэл `ErrStoreFull`, start 503 `{"error":"busy"}`;
  эхэлсэн нэвтрэлтийг устгахгүй.
- `CitizenIntermediatesPEM` (02 → 03 → 04, `pades/internal/eidcrypto/chain`-тэй байт-ижил — тестээр тулгана);
  `IntermediatesPEM` nil бол анхдагч — README-ийн `TrustConfig{TrustAnchorsPEM: []string{NationalRootCAPEM}}` жишээ шууд
  ажиллана (өмнө `intermediates` хувьсагч тодорхойгүй, өгөхгүй бол гинж тасарна).
- **`pades.Complete`: LTV retry** (TS 0.18.3-тай ижил) — OCSP/CRL цуглуулалт унавал ижил state, гарын үсэг, TSA
  timestamp-аар өөрөө дахин оролдоно: `CompleteOptions.LTVRetries` (`*int`; nil = `DefaultLTVRetries` 2, нийт 3, хүлээлт
  ~1 с, ~3 с + 0–25% jitter; 0 — унтраах; 0–10-аас гадуур → `REQUEST_INVALID`); бүгд унавал `LTV_UNAVAILABLE`; ctx
  цуцлалт хүлээлтийг тасална. PIN дахин асуухгүй. Портал (eidmongolia) өөрийн retry-г (!161) устгахаар төлөвлөж байна.
- **`NewOCSPChecker`: олгогч өөрөө зурж, хариундаа ӨӨРИЙН гэрчилгээг шигтгэсэн OCSP хариу** (RFC 6960 §4.2.2.2-оор
  хүчинтэй) `x/crypto/ocsp`-д «bad OCSP signature» гэж татгалзагддаг байв (шигтгэсэн cert-ийг issuer-ээр зурагдсан байхыг
  шаарддаг). Шигтгэсэн cert нь issuer мөн (байт-ижил эсвэл subject+SPKI — дахин олгосон хуулбар) бол хариуг issuer-ийн
  түлхүүрээр шалгана; delegated responder (EKU OCSPSigning) зам хэвээр, өөр түлхүүрээр зурсан бол signature алдаа.
  Хаана: `ocsp.go`; тест `TestOCSPIssuerSignedEmbeddedIssuer` (засваргүйгээр унадгийг шалгасан). Портал түр
  `ocsp_issuer_signed.go` transport-оор тойрч байгаа — **v0.6.0-аас тойрох шаардлагагүй**.
- Contract тест: discovery-ийн `pdfSigning.registerErrorCodes` == `PDFRegisterErrorCodes` (олонлогоор); CA-д талбар
  гарахаас өмнө skip + WARN.
- `PDF.RegisterSignature`-ийн 80 с (`DefaultPDFTimeout`) хэвээр; TS 0.19.0 ижил болсон (өмнө TS 15 с).

Шилжих: `AuthVerify(ctx, ch.ChallengeID, …)` → `AuthVerify(ctx, ch, …)`; `CheckKeyUsage: true`-г устгаж болно (нөлөөгүй);
тест/dev-ийн өөр CA-тай орчин → `AllowAnyIssuer: true`.

Хаана: `validator.go`, `certchoice.go`, `roots.go`, `token.go`, `client.go`, `eidlogin/eidlogin.go`, `pades/complete.go`,
`contract_test.go`, README, `doc.go`.
Шалгасан: `go vet ./...`, `go test ./...`, `go test -tags contract -run Contract .` (4 pass, 1 skip),
`GOOS=linux GOARCH=amd64 go build ./...`. Шинэ тест: PIN1 гарын үсэг ValidateSign-д унах, анхдагч issuer,
`TestCertificateLevelFromCertificate`, `TestCitizenIntermediatesPEM`, token auth-ийн локал шалгалт (CA руу явахгүй),
`TestDefaultStartLimit`, `TestWindowLimiterFullFailsClosed`, `TestMemoryStoreCap`, `TestCompleteLTVRetry` (2 унаад 3 дахь
нь golden-той байт-ижил; 3 унавал LTV_UNAVAILABLE; 0; -1/11; ctx cancel).
Прод DB (read-only, 2026-10-16): идэвхтэй утасны SIGN 66/66 QcCompliance-тэй, AUTH 67/67 KU DS|KE, токен AUTH 3 KU DS,
токен SIGN 3 qc-гүй — бүгд «eID Mongolia Issuing CA»-аас; анхдагч солигдсоноор одоогийн иргэд унахгүй.

## v0.5.2 — 2026-10-16

### Нэмэгдсэн

- **`POST /pdf/signatures`-ийн `Code*` тогтмолууд ба `PDFRegisterErrorCodes`** — CA main `pades_register.go`,
  `handlers_pdf.go` (2026-10-16)-ийн бүх код: `CodeRequestTooLarge`, `CodeCMSInvalid`, `CodeSignatureInvalid`,
  `CodeTimestampInvalid`, `CodeSignerMismatch`, `CodeSignerCertInvalid`, `CodeTokenCertInvalid`, `CodeTokenOrgMismatch`,
  `CodeSessionMismatch`, `CodeSessionNotComplete`, `CodeSessionFailed`, `CodeClaimedRoleMismatch`, `CodeDocIDConflict`,
  `CodeRegistryConflict`, `CodeDocNotFound`, `CodePriorMismatch` (+ одоо байгаа `CodeRequestInvalid`,
  `CodeRepresentationRevoked`, `CodeRateLimited`, `CodeStateUnavailable`). Яагаад: TS SDK 0.18.3-ийн
  `PDF_REGISTER_ERROR_CODES`-тэй нийцүүлэх (contract журам). Хаана: `pdfregister.go`.

Шалгасан: `go vet ./...`, `go test ./...` (шинэ `TestPDFRegisterErrorCodes`), `GOOS=linux GOARCH=amd64 go build ./...`.

- **`NewOCSPChecker` (портал өөрийн ocsp.go-г үүгээр солиход):**
  - `OCSPOptions.Observe func(OCSPObservation)` — шалгалт бүрд (кэшээс ч) `Status`, `Responder` URL, `Duration`, `Cached`,
    `Err`; serial/нэр орохгүй.
  - Хариугүй үед `RevocationUnknown` + `*OCSPError` (`Kind`: no_responder / no_issuer / timeout / network / http_status
    (+`HTTPStatus`) / responder_status / parse / signature / invalid; `errors.Is(err, ErrOCSPNoAnswer)`). Өмнө нь
    `RevocationUnknown, nil` — шалтгаангүй. `Validator.CheckRevocationWith` үүнийг unknown-оор горимоор шийднэ (soft →
    `unchecked`, nil; hard → `*ValidationError{Cause}`; `ValidationError.Unwrap` нэмэгдсэн) — `eidlogin`-ий зан хэвээр.
    **Анхаар:** checker-ийг шууд дууддаг код одоо `err != nil` авна (status нь `RevocationUnknown` хэвээр).
  - Кэш = min(`CacheTTL` (анхдагч 5 мин; сөрөг = кэшгүй), хариуны `NextUpdate` − одоо).
  - Delegated responder (RFC 6960 §4.2.2.2): ocsp.eidmongolia.mn-ийн бодит хариу (санамсаргүй serial, status unknown,
    «eID OCSP Responder» шигтгэсэн, EKU OCSPSigning) `testdata/ocsp-eid-delegated.der`-ээр тест — x/crypto
    `ParseResponseForCert` болон SDK-ийн шалгалт аль хэдийн зөвшөөрдөг байсныг баталгаажуулав (татгалзалт
    давтагдаагүй); өөр олгогчоор → `signature`.
  Шалгасан: `go test ./...`, `go test -race -run 'OCSP|Revocation'` (шинэ: TestOCSPErrorKinds, TestOCSPObserveAndNextUpdateCache,
  TestOCSPRealDelegatedResponder; TestOCSPChecker typed алдаагаар шинэчлэгдсэн), eidlogin тестүүд ногоон.
### README: share «туг унтраалттай» тэмдэглэл хасав

- **Юу/яагаад:** CA (ca-eidmongolia-mn !374) `rp./share`-ийн туг хасагдаж үргэлж асаалттай; README-ийн callout ба 503
  мөрийг шинэчлэв. Код өөрчлөгдөөгүй — `SHARE_DISABLED` код хуучин CA-д нийцүүлж хэвээр.
- **Шалгасан:** зөвхөн README; `grep -n "унтраалттай" README.md` — 0.

## v0.5.1 — 2026-10-16

### Нэмэгдсэн — токены сунгалтын scope түгжээ: TOKEN_SCOPE_CHANGE (CA !373)

- **Юу:** `CodeTokenScopeChange` (`TOKEN_SCOPE_CHANGE`), `CodeTokenInUse` (`TOKEN_IN_USE`) тогтмол;
  `c.Token.CertificateInfo(ctx)` → discovery-ийн `tokenCertificate` блок (`TokenCertInfo`, `ScopeLockedOnRenewal`);
  `IssueCertificate` / `CertificateResult`-ийн doc, `TokenCertSessionBlock.ErrorCode`-ийн жагсаалт, README §3.7-д дүрэм.
- **Яагаад:** CA main 0d1f3f63 (!373): ижил `tokenSerial` дээр ACTIVE бүртгэлтэй үед сунгалт scope-ийг (хувийн ↔
  байгууллага, өөр `onBehalfOf`) солих гэвэл `POST /token/certificate`, `GET /token/certificate/{id}` 409
  `TOKEN_SCOPE_CHANGE`, session-ий `tokenCertificate.errorCode` мөн; override үгүй — иргэн eID апп-аас токеноо
  цуцлаад шинээр олгуулна. Discovery: `tokenCertificate.scopeLockedOnRenewal: true`.
- **Хаана:** `token.go`, `types.go`, `README.md`, `portal_gaps_test.go`, `contract_test.go`.
- **Шалгасан:** `gofmt`, `go vet`, `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build ./...`,
  `go test -tags contract -run Contract` (live discovery-д `scopeLockedOnRenewal: true`).

## v0.5.0 — 2026-10-16

- **Нэмэгдсэн — `Client.Share`: гарын үсэгтэй файлыг имэйлээр (CA `POST /share`).**
  - Юу: `Share(ctx, ShareRequest{File, Filename, To, Subject, Message, Lang}) (*ShareResult, error)` — multipart
    (`ShareResult{Sent, SHA256, Signatures, DocID, Raw}`); `ShareInfo(ctx)` — discovery-ийн `share` блок (`Enabled`,
    формат, хязгаар, `Quota`). Алдаа `*ShareError` (`APIError` embed + `Unwrap`; `Reason` (422), `Sent`/`Failed`/
    `Recipients` (502 MAIL_FAILED)); кодууд `CodeFileEmpty` … `CodeValidatorBusy`, `ShareErrorCodes`,
    `ShareReason*`, `ShareRecipient*`, `DefaultShareTimeout` (150 с).
  - Нэмэгдсэн: `PersonCertificate.IssuedAt`, `RevokedAt`, `RevocationReason` (RFC 5280 нэр).
  - Яагаад: CA main 0329ef95 (!371) — `rp./share` (туг `EID_SHARE_ENABLED`, одоогоор унтраалттай) ба `/certificates`-ийн
    шинэ талбарууд; портал Go SDK-аар дуудна. TS SDK 0.18.0-тэй ижил.
  - Хаана: `share.go`, `routes.go` (`routeShare`), `client.go`, `person.go`, `share_test.go`, `contract_test.go`
    (`TestContractShare`), README §3.6/§3.8/§5.
  - Шалгасан: `gofmt`, `go vet`, `go test -race ./...`, `GOOS=linux go build`, `go test -tags contract -run Contract`
    live discovery-тэй (share зам, multipart талбар, `share` блок).

## v0.4.0 (BREAKING) — 2026-10-15

- **v0.4.0 (BREAKING): PDF upload клиент устсан.** CA upload-д суурилсан PDF endpoint-уудыг устгасан (`POST
  /pdf/sign/prepare`, `GET /pdf/sign/{id}/document`, `/pdf/token/prepare|{id}/finalize|{id}/document` → 404;
  discovery `endpoints.pdf`-д зөвхөн `signatures`), session-ий `pdf` блок, `PDF_PREPARE_BUSY` / `DOCUMENT_PENDING`
  кодууд ч CA-д алга. SDK тэдгээрийг дуудсаар байсан тул `contract` CI улаан байв. TS SDK 0.15.0-тэй нийцүүлэв.
  Tag энэ PR-д үгүй — PR #18 (visible signature)-тэй хамт v0.4.0.
  - Устсан exported: `PDFService.Prepare`, `.Document`, `.TokenPrepare`, `.TokenFinalize`, `.TokenDocument`;
    `DocumentVerified`; `PDFPrepareInput`, `PDFPrepareSession`, `PDFDeviceLink`, `PDFSignerRef`, `PDFFlowNotification`,
    `PDFFlowDeviceLink`, `PDFTokenPrepareInput`, `PDFTokenPrepareSession`; `SessionResult.PDF`, `PDFSessionBlock`,
    `PDFSigner`, `PDFValidation`, `PDFPending` / `PDFReady` / `PDFFailed` / `PDFExpired`; `Config.PDFMaxBytes`,
    `DefaultPDFMaxBytes`; `CodePDFPrepareBusy`, `CodeDocumentPending` (`RetryableCodes`-оос ч).
  - Үлдсэн (клиент талын PAdES): `pades/`, `PDFService.RegisterSignature` (`POST /pdf/signatures`),
    `PDFSignatureRegistration`, `PDFMedium*`, `Sign.DigestForSigner` / `DeviceLinkForSigner`, certificate-choice.
    `Config.PDFTimeout` / `DefaultPDFTimeout` одоо зөвхөн `RegisterSignature`-д.
  - Шилжилт: `PDF.Prepare` → `Document` → `DocumentVerified`-ийн оронд `pades.Prepare` → `Sign.DigestForSigner` →
    `pades.Complete` → `PDF.RegisterSignature` (README §7). Токен: токен DTBS-ийг зурж `Medium: PDFMediumToken`.
  - Хаана: `pdf.go`, `pdftoken.go` (устсан), `routes.go`, `client.go`, `types.go`, `session.go`, `errors.go`,
    тестүүд (`client_test.go`, `portal_gaps_test.go` — түр алдааны тест `RegisterSignature` руу шилжсэн,
    `x509_gaps_test.go`, `routes_test.go`), README §3.4/§3.7/§5/English.
  - Шалгасан: `gofmt`, `go vet`, `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build ./...`,
    `go test -tags contract -run Contract` live discovery-тэй PASS (21 зам; `/token/auth/*` discovery-д орсон WARN —
    тусдаа).
- **PAdES: харагдах гарын үсэг (сонголттой) + golden v3 + гадны шалгалт (qpdf, pyHanko).**
  - Юу: `PrepareOptions.Appearance` (`page`, `x`, `y`, `width`, `height`, `lang`) — nil бол үл харагдах, v2 golden байт-ижил.
    Харагдах widget `/Rect` (CropBox-ийн харагдах эх, `/Rotate` 0/90/180/270), `/F 4`, `/P`, хуудасны `/Annots`-д
    (incremental), `/AP /N` form XObject (шахалтгүй, verify хуудасны фонт, өөрийн QR): нэр, үүрэг, «eID Mongolia-аар
    зурсан» / «Signed with eID Mongolia», огноо (+08), QR `https://ca.eidmongolia.mn/verify/<docID>/<revIndex>`.
    Дүрэм: `pades/APPEARANCE_SPEC.md` (хэмжээ/тойруулга/wrap/жижгэрэх, багтахгүй → `REQUEST_INVALID`, §5 validator).
  - Validator (own-signer): зөвхөн яг энэ widget + 11 /AP объектыг дахин үүсгэж байт-түвшинд тулгаж хүлээн авна; ObjStm
    доторх хуудсыг шууд объектоор дахин бичихийг (own, page/annots) зөвшөөрнө. Тайланд `visible` талбар.
  - DSS: давхардалгүй байдлыг (ижил DER → нэг stream, массивт нэг удаа; өмнөх DSS-ийн объектыг дахин ашиглах) PROFILE.md §7-д
    тодорхой бичиж, golden бүрд тест (`dssUnique`) — бичигч аль хэдийн ингэж ажилладаг тул гаралт өөрчлөгдөөгүй.
  - CI: `golden-external` job — golden гаралт бүрд `qpdf --check` ба pyHanko (INTACT/VALID/TRUSTED, DSS-ээс LT, timestamp,
    өөрчлөлтийн түвшин, харагдах).
- Хаана: `pades/prepare.go`, `pades/internal/core/{appearance,signature,vpage}.go`, `pades/internal/validate/{appearance,
  revisions,extract,validate}.go`, `pades/internal/padestest`, `pades/{APPEARANCE_SPEC,PROFILE}.md`, `pades/testdata/golden`
  (manifest + 5 тохиолдол, `input/quartz-rotated90.pdf`, `ci/pyhanko_check.py`), `.github/workflows/ci.yml`, README.
- Шалгасан: `TestGolden` (v2 тохиолдлын гаралт өөрчлөгдөөгүй — git diff), `TestOwnVisibleSignature` (хүлээн авах + 17
  халдлага), `TestAppearanceRejects`, `TestVisibleRect`, `TestNum100`; pdfsig (Signature is Valid), qpdf --check,
  pyHanko 0.37 (19 гарын үсэг OK), pdftoppm/PDFKit render, QR-ийг CIDetector-оор уншсан; gofmt, vet, `go test -race ./...`,
  linux build.
- Үлдсэн: CA `server/internal/validate`-д §5-ийг порт (тусдаа агент); native SDK-ууд (TS/Swift/Kotlin/.NET) v3 golden;
  PDFKit (macOS) `/Rotate`-тэй хуудсан дээрх widget-ийг зурдаггүй (poppler зурна) — шалгах.
- **Баримт/тайлбарын зөрүү (аудит 2026-10-15) + CHANGELOG нэгтгэл, guard.**
  - README: install `@v0.4.0`; хамаарал — `eid`/`eidlogin` стандарт сан + `golang.org/x/crypto/ocsp`, `pades` мөн
    `golang.org/x/text`; багцын зам `…/eid-mongolia-sdk-go/eidlogin`; RP бүртгэл — өргөдлийн API
    (`POST /v3/rp-applications`) засвартай (503 `rp_applications_maintenance`), имэйлээр; товчны CDN `@0.15.4`;
    `/token/auth/*` live discovery-д (`endpoints.token.auth_challenge` / `auth_verify`); `REPRESENTATION_REVOKED` =
    `RegisterSignature` ба токены гэрчилгээ олголт. `routeTokenAuth*` → `rpRoutes` (гэрээний тест fail-аар шалгана).
  - **BREAKING (v0.4.0-д):** `eid.CodeTSAUnavailable`, `eid.CodeLTVUnavailable` хасагдсан, `RetryableCodes`-оос ч — CA
    тэдгээрийг буцаадаггүй (CA main `af939ab0`-д шалгасан); клиент талын `pades.CodeTSAUnavailable` /
    `pades.CodeLTVUnavailable` хэвээр. Кодгүй 429/503 + `Retry-After` `Retryable()` хэвээр.
  - Тайлбар: `errors.go` (устсан `PDF_PREPARE_BUSY` / `DOCUMENT_PENDING` / document route-ийн дурдлага), `doc.go` /
    `client.go` (`eid` PDF угсрахгүй — зөвхөн `RegisterSignature`; угсралт = `pades`), `eidlogin.Identity.DocumentNumber`
    = төхөөрөмжийн UUID, `pades/doc.go` (байхгүй mobile/capi/wasm binding), `pades/WIRE.md` (golden nonce = §4).
  - `CHANGELOG.md`: v0.1.6 … v0.3.2 фрагментуудыг tag-аар тулгаж нэгтгэв (sign-session-gaps → v0.2.1; «CA хугацаа
    буцаадаггүй» нь v0.2.2-оос хуучирсныг тэмдэглэв); v0.4.0 (BREAKING) — Unreleased.
  - Guard: `scripts/changelog.sh` (`assemble` / `check-release` / `check-pr`); CI `changelog` job PR-д фрагмент шаардана;
    `.github/workflows/release.yml` — `v*` tag-д фрагмент үлдсэн, гарчиг алга эсвэл «Unreleased» бол улаан.
  - Шалгасан: live `/.well-known/eid`, `/mobile/app-config`, `/v3/rp-applications` (2026-10-15); `gofmt`, `go vet`,
    `go test ./...`, `GOOS=linux GOARCH=amd64 go build ./...`.

## 0.3.2 — 2026-10-14

- **v0.3.2 — `eidlogin`: регистрийн oracle хаалт (decoy + PushFloor), OCSP цуцлалт, аудитын hook (TS 0.15.2-тэй ижил).**
  - **G1 (Critical) — бүртгэлийн oracle.** Push start eID-ийн татгалзалд (танихгүй дугаар) 502, бүртгэлтэйд 200 өгдөг,
    хугацааны доод хязгааргүй байсан — нэвтрээгүй хэн ч регистр eID-д бүртгэлтэй эсэхийг шалгаж болох байв. Одоо eID-ийн
    өөрийн JSON 4xx (401/403/429-ээс бусад) → decoy session: бодит хариутай ижил `{mode, vc (5 оронтой), expiresIn}`,
    ижил cookie, `status` нь eID-ээс асуулгүй `Poll`-ын хугацаанд барьж PENDING → TTL-ийн дараа EXPIRED. Push start-ийн
    хариу бүр (бодит, decoy, 502) ≥ `PushFloor` (анхдагч 1 с, ctx тасарвал зогсоно). 5xx / холболт / JSON бус 4xx (proxy)
    / 401 / 403 → 502, 429 → 429 (eID порталын `HandleEIDStartByNationalID`-тэй ижил: тасалдлыг нуухгүй, дугаараас
    хамааралгүй). Хязгаар decoy-д ч үйлчилнэ. Push-ийн CA `TIMEOUT` → `EXPIRED` (decoy-той ижил төгсгөл). Унтраах: `DisableDecoy`, `DisablePushFloor` (анхааруулгатай).
  - **G2 (High) — цуцлалт.** `finish` нь `ValidateAuth`-ийн дараа гэрчилгээг AIA OCSP-оор шалгана (`Config.Revocation`,
    nil = шинэ `eid.NewOCSPChecker`). revoked / unknown → FAILED `VALIDATION` (500 биш); хариугүй → soft-fail
    (порталын `EID_OCSP=soft`: зөвшөөрч Warn, `Identity.Revocation = unchecked`), `RevocationMode: eid.RevocationHardFail`
    → FAILED. `DisableRevocation` — унтраана. Шинэ: `eid.NewOCSPChecker` (олгогч/OCSPSigning responder-ийн гарын үсэг,
    serial, thisUpdate [−48ц, +5мин], nextUpdate, 2 с timeout, redirect-гүй, 16 KiB, good-ийг 5 мин кэш),
    `Validator.CheckRevocationWith`, `Identity.Revocation`.
  - **G3 (Medium) — аудит.** `Config.OnEvent(ctx, kind, sessionID, meta)`: `push_sent` (meta `decoy`), `push_limited`,
    `refused`, `expired`, `unverified` (`reason`), `flow_refused`, `success` (`flow`, `revocation`), `failed`
    (`endResult`). Регистрийн дугаар биш `pushKey` = HMAC-SHA256(`AuditKey`, дугаар); токен/нууц орохгүй.
- Хаана: `ocsp.go`, `validator.go`, `eidlogin/eidlogin.go`, `eidlogin/security_test.go`, `ocsp_test.go`,
  `eidlogin/eidlogin_test.go` (хуурмаг цаг, event бүртгэл), `README.md` §2, §4.
- Шалгасан: `TestPushDecoyIndistinguishable` (талбар, vc хэлбэр, floor 1 с хуурмаг цагаар, decoy poll eID-ээс асуухгүй,
  EXPIRED, event-д decoy, meta-д регистр алга), `TestPushOutageNotDecoy` (500/proxy400/401 → 502), `TestDecoyAndFloorOptOut`,
  `TestDecoyRateLimited`, `TestRevocation` (revoked/checker алдаа/hard-fail → FAILED VALIDATION; анхдагч soft → unchecked;
  good; disabled), `TestEvents`, `TestOCSPChecker` (good/revoked/unknown, delegated responder, хуучин thisUpdate, 5xx,
  буруу issuer, кэш); `gofmt`, `go vet`, `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build ./...`.
- **PAdES бүртгэл: горим A-ийн өмнөх гарын үсэгтэй баримт + `Created`.**
  - Юу: горим A-аар (CA угсарсан) эхэлж зурагдсан баримтад нэмж зурахад `RegisterSignature` 409 `PRIOR_MISMATCH` авдаг
    байв — `pades.Registration` бүх өмнөх мөрийг CMS-ээр илгээж, `PriorRevisionSHA256`-г дуудагчид гараар ангилуулдаг. CA
    өмнөх мөр бүрийг өөрийнх нь түлхүүрээр таньдаг (клиент — `cms_sha256`, горим A — `sig_rev_sha256` = `sha256(doc[0 :
    ByteRange[2]+ByteRange[3]])`; CA `persistence/models.go` `PDFPrior.Covers`, `pades_finalize.go` `sha256(signed)`), файлаас
    ялгах боломжгүй (профайл 1:1).
  - Засвар: `pades.Registration` → `PriorSignatures []eid.PDFPriorSignature` (`json:"-"`, CA руу илгээхгүй);
    `RegisterSignature` эхлээд CMS-ээр, `PRIOR_MISMATCH` бол эхний k-г revision-оор (k = 1…n), n ≤ 4 бол бүх хослол
    (`priorSplits`, TS-тэй ижил дараалал). `PriorRevisionSHA256` гараар өгвөл хуучин зан.
  - `PDFSignatureRegistered.Created` — 201 → true, 200 (давталт) → false (`httpDoer.postJSONStatus`).
- Хаана: `pdfregister.go`, `client.go`, `pades/register.go`, README.
- Шалгасан: `TestRegisterSignatureReplayAndPriorMismatch`, `TestPriorSplits`, `TestRegisterSignature` (Created),
  `pades` 2 дахь гарын үсэг: `PriorRevisionSHA256[0] == эхнийх SigRevSHA256`, `PriorSignatures`; gofmt, vet,
  `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build ./...`.
- Үлдсэн: native SDK (Swift/Kotlin/.NET)-д ижил засвар тусдаа.

## 0.3.1 — 2026-10-14

- **v0.3.1 — `eidlogin`: өөрийн хязгаар өгөхөд анхдагч push хязгаар алдагддаг байсан (TS 0.15.1-тэй зэрэгцүүлсэн).**
  - `Config.RateLimit` өгөхөд анхдагч (push — нэг дугаарт 3/мин, MFA fatigue) чимээгүй унтардаг байв. Одоо
    `Config.RateLimits map[string]RateRule` (`"start"` | `"push"`) `DefaultRateLimit()`-тэй төрөл тус бүрээр нэгтгэгдэнэ
    (`RateRule{Max, Window}` санах ойн цонх | `{Func}` | `{}` хязгааргүй); `Config.RateLimit` функц анхдагч ДЭЭР
    нэмэгдэнэ. `DefaultRateLimit()` export (шинэ map). Буруу түлхүүр / Window ≤ 0 → `New` алдаа.
  - README: хязгаарлалтын хэсэг, товчны CDN 0.15.1, dark токен (`--eid-<нэр>-dark`) заалт, install v0.3.1.
- Хаана: `eidlogin/eidlogin.go`, `eidlogin/eidlogin_test.go`, `README.md` §2.
- Шалгасан: `TestRateLimitsMergeKeepsDefaultPush` (зөвхөн start өгөхөд push 3/мин идэвхтэй), `TestRateLimitFuncAddsToDefault`,
  `TestRateLimitsOverridePush` (window/off/func, start window), `TestDefaultRateLimitAndValidation`; `gofmt`, `go vet`,
  `go test ./...` (+ `-race` eidlogin), `GOOS=linux GOARCH=amd64 go build`.

## 0.3.0 — 2026-10-14

### Клиент талын PAdES — Go reference (`pades`)

- **Юу:** CA-ийн PAdES бичигч (`server/internal/pdfsign/pades/*`) ба нийтийн шалгагч (`validate/*`)-ийг extract хийв:
  `pades.Prepare` (хөнгөн precheck → verify хуудас → R_sig → DTBS), `pades.Complete` (гарын үсэг шалгах → RFC 3161 →
  CMS → OCSP/CRL (AIA/CDP, genTime-ийн дараа) → DSS → self-validation) → `*Completed` (CA-ийн бүртгэлийн талбаруудтай),
  `pades.Verify` (CA-ийн /v3/validate/pdf-тэй ижил тайлан). Verify хуудас — хоёр хэлтэй (mn анхдагч, en), минимал детерминист writer + өөрийн QR
  (pdfcpu/fpdf/go-qrcode-гүй). Профайлын баримт: `pades/{PROFILE,PAGE_SPEC,PRECHECKS,WIRE}.md`.
- **Яагаад:** PDF eID-ийн серверт очихгүй (CA docs/PADES_CLIENT_SIDE.md); Go нь TS/Swift/Kotlin/C# native SDK-уудын
  reference, golden vector-оор байт-ижил байдлыг баталгаажуулна.
- **Хаана:** `pades/`, `pades/assets` (Noto Sans OFL, zlib тогтмол asset + metrics.json), `pades/internal/{core,qr,
  validate,eidcrypto,padestest}`, golden `pades/testdata/golden/`. `go.mod`: go 1.22 → 1.25 (тестийн хамаарал pdfcpu
  v0.12.0), CI matrix 1.25/stable.
- **CA-аас зөрөх:** xref stream шахалтгүй; шууд `/Info` trailer-т хуулна; `/M` үргэлж +08:00; verify хуудас шинэ writer;
  үндэсний CRL-ийг `https://crl.eidmongolia.mn/` толиноос татна;
  prepare-д validator биш хөнгөн precheck (бүртгэлийн оронд eID олгогч + SubFilter-ээр «гадны» гарын үсэг); цуцлалтын
  төлөв DSS-ийн OCSP/CRL-ээс; задлагч процесс дотор.
- **Шалгасан:** `go test -race ./...` (Go 1.25, 1.27), golden (prepare+complete байт-ижил), desktop Swift golden,
  e2e (RSA/ECDSA r‖s, DER), QR-ийг CoreImage-ээр, хуудсыг PDFKit-ээр уншиж (текст ToUnicode, QR decode) шалгав,
  `GOOS=linux GOARCH=amd64 go build ./...`.
- **Бүртгэл (CA §4.3/§4.3.1):** `eid.PDFSignatureRegistration` + `PDFService.RegisterSignature` (`POST /pdf/signatures`,
  CA dto-тэй ижил бие, `signerEtsi`), `pades.Registration(completed, opts)`; `Representation.ClaimedRole` (CA !352).
  RSASSA-PSS гарын үсгийг `Complete` `REQUEST_INVALID`-аар татгалзана (DigestForSigner/DeviceLinkForSigner-ийн анхдагч
  sha256WithRSAEncryption). README-ийн жишээ `pades/example_test.go`-оор compile хийгдэнэ; contract тест
  `TestContractPDFSignaturesBody` (discovery-ийн биеийн талбар = SDK-ийн JSON түлхүүр).

## 0.2.2 — 2026-10-14

- **v0.2.2 — CA !357 (fd3acf14, прод 2026-10-14)-тэй нийцүүлэв.**
  - `ExpiresAt`: session start хариуны CA-ийн `expiresAt` (RFC 3339) — sign / certificate-choice (push, device-link,
    linked) ба auth (push, device-link). Талбаргүй / задрахгүй (хуучин CA) үед sign/cert-choice-д `SessionExpiry`
    тооцоолол, auth-д тэг.
  - `errors.Is` sentinel: `ErrNoSigningCertificate` (409 `NO_SIGNING_CERTIFICATE`), `ErrCertChoiceInvalid` (409
    `CERT_CHOICE_INVALID`), `ErrRequestInvalid` (400 `REQUEST_INVALID`) — `*APIError.Is` нь `Code`-оор тулгана;
    `Code*` тогтмолууд. `errors.As(&*APIError)` хэвээр.
- Хаана: `auth.go`, `sign.go`, `certchoice.go`, `errors.go`, `types.go`, `README.md`.
- Шалгасан: `session_start_test.go` (CA expiresAt / fallback / typed алдаа); `gofmt`, `go vet`, `go test ./...`,
  `GOOS=linux go build`.

## 0.2.1 — 2026-10-14

- **v0.2.1 — `eidlogin` засвар (TS 0.14.1-тэй зэрэгцүүлсэн; demo интеграцаас ирсэн асуудлууд).**
  - `Identity.SessionID` нэмэв (DocumentNumber, Certificate байсан) — RP дараагийн алхамд (гарын үсэг, гэрчилгээ холбох).
    Tx нь OnSuccess-оос өмнө атомар устгагдах (нэг удаа) хэвээр — баримтжуулав.
  - `ForwardedClientIP(hops)` (XFF баруунаас n, эсвэл X-Real-IP; hop дутвал "") ба `RemoteAddrIP` — `Config.ClientIP`-д
    бэлэн; TS-ийн `trustProxy`/`getClientIp`-тэй ижил дүрэм. `ClientIP` nil бол `New` нэг удаа Warn.
  - README: клиент IP, Redis store жишээ (go-redis, SDK хамааралгүй), eID аппын доод хувилбар (iOS 2.2.3 (59),
    Android 2.2.3 (60); app-config min iOS 2.2.7 / Android 83 — 10-14 шалгасан), товчны CDN 0.14.1.
- Хаана: `eidlogin/eidlogin.go`, `eidlogin/eidlogin_test.go`, `README.md` §2.
- Шалгасан: `TestQRFlow` (SessionID/DocumentNumber/Certificate), `TestForwardedClientIP`, `TestForwardedClientIPRateLimit`;
  `gofmt`, `go vet`, `go test ./...`, `GOOS=linux go build`.
- **Sign session-ий дутуу хэсгүүд (client-side PAdES)** — v0.2.1-д гарсан (PR #11 tag-гүй; v0.2.1 release-д
  орсон). Портал HASH sign (RAW_DIGEST_SIGNATURE, digest = 32 байт DTBS)-д олсон дутуу:
  - **Device-link sign:** `Sign.DeviceLinkByEtsi` / `DeviceLinkByDocument` (`POST /signature/device-link/{etsi|document}/…`)
    — `initialCallbackUrl`, `interactions`, `fileName`, `onBehalfOf`, RAW_DIGEST параметрүүд. `DeviceLinkSession.LinkInput`
    — auth/sign/cert холбоосын `BuildDeviceLink` оролтыг session-оос угсарна. `SignContext` (`NotificationSession.Sign`,
    `DeviceLinkSession.Sign`) — илгээсэн digest/hash/алгоритм/interactions/callback.
  - **Certificate-choice:** `Sign.CertificateChoiceByEtsi`, `Sign.CertificateChoiceDeviceLink` (зөвхөн QR — CA-ийн хүсэлт
    callback авдаггүй), `Validator.ValidateCertificateChoice` → `Signer{Certificate, DocumentNumber, CertChoiceSessionID}`.
  - **Signer-ээр зурах:** `Sign.DigestForSigner` (`/signature/notification/linked/{documentNumber}` +
    `linkedSessionID`, cert choice-гүй бол `/notification/document/…`), `Sign.DeviceLinkForSigner`
    (`/signature/device-link/document/…`). Олон утастай иргэнд etsi-ээр эхлүүлбэл өөр утас зурж CMS эвдэрдэг тул
    documentNumber-аар л. Анхдагч `sha256WithRSAEncryption` + SHA-256; digest-ийн уртыг хүсэлтээс өмнө шалгана.
  - **`ValidateSignOptions.ExpectedAlgorithm`** — хүссэн RSA алгоритмаас өөр хариу (ж: PKCS#1 хүссэнд rsassa-pss) →
    `*ValidationError`; CA-ийн хуучин threshold-ECDSA credential-ийн `ecdsa-with-SHA256`-ийг зөвхөн EC P-256 + SHA-256
    үед. **`ExpectedCertificate`** — certificate-choice-ийн гэрчилгээнээс өөрөөр зурсан бол татгалзана.
  - **`ExpiresAt`** — тухайн үед CA session start хариунд хугацаа буцаадаггүй байсан (`sessionID`/`vc`, device-link-д
    token/secret) тул
    sign / cert-choice session-д хүсэлтээс өмнөх цаг + `Config.SignSessionTTL` (анхдагч `DefaultSignSessionTTL` = 600с
    = CA `EID_SIGN_SESSION_TTL_SECONDS`; CA админ 60–1800с болгож болно). `SessionExpiry` туслах. v0.2.2-оос CA (!357) `expiresAt` буцаадаг
    болсон тул SDK түүнийг авна; энэ тооцоолол зөвхөн талбаргүй (хуучин) CA-д.
  - 5 шинэ зам `rpRoutes`-д (live `/.well-known/eid`-д бүгд бий).
  - Хаана: `sign.go`, `certchoice.go`, `validator.go` (precheck → `sessionDone` + `leafOf`), `devicelink.go`, `types.go`,
    `routes.go`, `client.go`, README §3.3.
- Шалгасан: `sign_gaps_test.go` (device-link body/зам/LinkInput байт-ижил, ExpiresAt, cert choice body түлхүүрүүд,
  ValidateCertificateChoice, DigestForSigner linked/document/device-link + буруу оролтод хүсэлт явахгүй,
  ExpectedAlgorithm/ExpectedCertificate). `gofmt`, `go vet ./...`, `go test -race ./...`, `go test -tags contract`
  (live discovery), `GOOS=linux GOARCH=amd64 go build ./...`.

## 0.2.0 — 2026-10-14

- **BREAKING (v0.2.0): `oidc` багц хасагдсан; «eID-ээр нэвтрэх» = `eidlogin.Handler` (net/http) RP-API дээр.** eID-ийн
  OIDC provider (`login.eidmongolia.mn`) хасагдсан (2026-10-14 шийдвэр) тул `oidc/` (client, contract тест) ба README
  §2 OIDC устсан — openid-configuration прод дээр 404 болж `contract` job улаан байсан. Оронд нь Smart-ID RP-үүдийн
  хэв маяг: `eidlogin.New(Config{Client, OnSuccess, CallbackURL, Store?, RateLimit?, ClientIP?, …})`, `/auth/eid/`
  дор mount — `start` (POST qr | push; GET `?mode=web2app` → 302 eID апп, буцах хөтчийн `retScheme`/`retPkg` hint
  UA-аас), `status` (PENDING + секунд тутмын QR / WAIT_CALLBACK / OK / FAILED / EXPIRED), `callback` (Web2App +
  `userChallengeVerifier`). Төлөв серверт (`Store`, анхдагч `NewMemoryStore`), хөтчид HttpOnly cookie
  (`<sessionId>.<binding>`); callback зөвхөн эхлүүлсэн хөтчид (login CSRF); JSON-only POST + `Sec-Fetch-Site`; push-д
  анхдагч 3/мин нэг дугаарт; иргэн (`Identity`) зөвхөн `ValidateAuth`-ийн дараа `OnSuccess`-д. Хариуны хэлбэр TS SDK
  0.14.0-ийн `createEidLogin`-тэй ижил (хөтчийн товч `<eid-login-button>`). `Client.RPName()` нэмэгдсэн.
- Хаана: `eidlogin/eidlogin.go`, `eidlogin/eidlogin_test.go`, `client.go`, `doc.go`, `README.md` §2, `.github/workflows/contract.yml`.
- Шалгасан: `eidlogin` тест — fake RP-API (httptest) БОДИТ ACSP_V2 RSA-PSS гарын үсэг буцааж, `Validator` жинхэнээр
  шалгана: QR / push / Web2App, cookie binding, cookie-гүй callback татгалзах, буруу verifier, хуурамч гарын үсэг,
  flowType зөрөх (relay), CSRF, rate limit, нэг удаагийн OnSuccess. `gofmt`, `go vet ./...`, `go test -race ./...`,
  `GOOS=linux GOARCH=amd64 go build ./...`, `go test -tags contract -run Contract ./...` (live) ногоон.

## 0.1.6 — 2026-10-14

- **OIDC: `mtls_endpoint_aliases` (RFC 8705 §5)** — v0.1.6. `login.` хост mTLS хийдэггүй тул `require_mtls`-тэй RP
  code солиход `login.eidmongolia.mn/oauth2/token` дээр `401 invalid_client` авдаг байв. CA !347 discovery-д
  `mtls_endpoint_aliases.token_endpoint` (`https://rp.eidmongolia.mn/oauth2/token`, RP client cert шаардана) нэмсэн.
  `oidc.Discovery.MTLSEndpointAliases map[string]string`; `oidc.Config.UseMTLSEndpointAliases` (анхдагч false) — true +
  alias байвал token хүсэлт alias руу; alias алга бол `TokenEndpoint` руу буцна; alias https биш бол
  `ErrDiscoveryFailed`. Client cert нь `Config.HTTPClient`-ийн Transport-оор (RP-API-тай ижил). README: «mTLS-тэй RP».
  Хаана: `oidc/oidc.go`, `oidc/oidc_test.go`. TS SDK 0.13.0-тай ижил.
- Шалгасан: `TestMTLSEndpointAliases` — флагтай → alias, флаггүй → `token_endpoint`, alias алга → fallback, `http://`
  alias → `discovery_failed` (token хүсэлт явахгүй). `gofmt`, `go vet ./...`, `go test -race ./...`,
  `GOOS=linux GOARCH=amd64 go build ./...`.

## 0.1.5 — 2026-10-14

Эрхийн төрөл ба эх үүсвэрийн нэр (`rightTypeLabel`, `sourceLabel`, CA !344) — TS SDK 0.12.1-тэй ижил, additive:

- **`RightTypeLabel` / `SourceLabel`** (CA !344, additive) — `Representation.RightTypeLabel`, `Representation.SourceLabel`
  (`GetRepresentations`) ба session-ий `OrgResult.RightTypeLabel` (`OnBehalfOf`; тэнд `Source` байхгүй),
  `json:"…,omitempty"`. Эрхийн төрөл (ADMIN → «Админ» / Administrator, MANAGER → «Гарын үсэг зурагч» / Signatory) ба
  эх үүсвэрийн (REGISTRY → «Улсын бүртгэл» / State registry, MANUAL → «Захирал нэмсэн» / Added by the director) хүнд
  харуулах нэр, CA нэг газраас (`orgrole.RightTypeLabel` / `SourceLabel`, CA `docs/ORG_LOGIN.md` §4а); хэл нь
  `RoleLabel`-тэй ижил (`Config.Language` → `Accept-Language`). Клиент `RightType`/`Source` кодыг өөрөө орчуулахгүй.
  Хуучин CA-д хоосон. README: «RoleLabel / RightTypeLabel / SourceLabel». TS SDK 0.12.1-тэй ижил.
- Шалгасан: `TestRightTypeSourceLabel` (representations / session decode, хуучин хариунд хоосон, omitempty).
  `gofmt`, `go vet`, `go test -race`, `GOOS=linux go build`.

## 0.1.4 — 2026-10-14

Албан тушаалын нэр (`roleLabel`, CA !339) — TS SDK 0.12.0-тэй ижил, additive:

- **`RoleLabel`** (CA !339, additive) — `Representation.RoleLabel` (`GetRepresentations`) ба session-ий
  `OrgResult.RoleLabel` (`OnBehalfOf`), `json:"roleLabel,omitempty"`: албан тушаалын хүнд харуулах нэр, CA нэг газраас
  (`server/internal/orgrole`, CA `docs/ORG_LOGIN.md` §4а) өгнө. `Role` нь машин утга (`ceo` / `founder` / `stakeholder`
  эсвэл MANUAL текст) — клиент өөрөө орчуулахгүй, `RoleLabel`-ийг харуулна. Хуучин CA-д хоосон.
- **`Config.Language`** — дуудлага бүрд `Accept-Language` (`"mn"` | `"en"`); `""` = илгээхгүй (сервер mn). TS SDK
  0.12.0-ийн `language`-тэй ижил.
- Шалгасан: `TestRoleLabel` (representations / session decode, хуучин хариунд хоосон, omitempty), `TestLanguageHeader`
  ("" → header алга, "en", " mn " → "mn"). `gofmt`, `go vet`, `go test -race`, `GOOS=linux go build`,
  `go test -tags contract` (live).

## 0.1.3 — 2026-10-14

Порталын (eid-mongolia-mn !140) SDK шилжилтийн үлдэгдэл — TS SDK 0.11.0-тэй ижил:

- **Validator гинж → `x509.Certificate.Verify`** (аюулгүй байдал, High). Өмнө гинжийг гараар угсардаг байсан тул
  pathLenConstraint, name constraints, завсрын CA-ийн EKU, CA-ийн keyCertSign, үл таних critical extension шалгагддаггүй
  байв (портал өмнө нь x509.Verify-аар шалгадаг байсан — SDK руу шилжихэд регресс). Одоо `Roots` = trust anchor,
  `Intermediates` = `IntermediatesPEM`, `KeyUsages`: auth → clientAuth, sign → emailProtection (CA `ca_profile.go`:
  P-CITIZEN-AUTH = clientAuth+emailProtection, P-CITIZEN-SIGN = emailProtection), `CurrentTime` = leaf-ийн хугацаанд
  хавчсан мөч (`ClockSkew`). `AllowedIssuerSKIs`, `CheckKeyUsage`, revocation hook — хэвээр, Verify-ийн дараа.
  **Зан төлөвийн өөрчлөлт:** EKU-г `CheckKeyUsage`-ээс үл хамааран гинжийн шалгалт шалгана — гарын үсгийн
  (emailProtection-only) гэрчилгээ `ValidateAuth`-д татгалзагдана. certificatePolicies шалгахгүй (Go 1.22) — CA-ийн
  гинжинд policyConstraints / inhibitAnyPolicy алга. Алдааны текстэд subject орохгүй (шалтгааны ангилал л).
- **`Config.PDFMaxBytes`** (`DefaultPDFMaxBytes` = 64 MiB) — `PDF.Document` / `PDF.TokenDocument`; хэтэрвэл
  **`*ResponseTooLargeError`** (`Op`, `Limit`). JSON хариу 4 MiB-ээс хэтэрвэл мөн `*ResponseTooLargeError` (өмнө нь
  таслагдаад задлалтын алдаа болдог байсан).
- **`RepresentationsResponse.Raw`** — `GetRepresentations`-ийн түүхий JSON.
- **USB токены PAdES:** `PDF.TokenPrepare` (multipart, токены SIGN гэрчилгээ + `OnBehalfOf`), `PDF.TokenFinalize`
  (түүхий r||s 64 байт), `PDF.TokenDocument` — CA `docs/PADES_SIGNING.md` §16.5, `TOKEN_CERT.md`. Замууд CA-д бий ч
  `/.well-known/eid`-д алга тул `rpRoutesUndiscovered` (гэрээний тест WARN).
- Шалгасан: бодит гинж (01→02→03→04) ба CA-ийн бодит иргэний AUTH/SIGN (RSA + токены EC) гэрчилгээнүүд Go
  `x509.Verify`-аар амжив (репод оруулаагүй — хувийн мэдээлэлтэй); тест: бодит профайлын хуулбар гинж амжина,
  pathLen / завсрын EKU / CA:false / keyCertSign-гүй / хугацаа дууссан завсрын / буруу root / MDDC дутуу / name
  constraints / үл таних critical extension → татгалзана; 04 ← 03 бодит гэрчилгээ x509.Verify. `gofmt`, `go vet`,
  `go test -race` (1.25 + 1.22), `GOOS=linux go build`, `go test -tags contract` (live).

## 0.1.2 — 2026-10-14

Порталыг (eid-mongolia-mn, MR !140) SDK руу шилжүүлэхэд илэрсэн дутагдлууд — бүгд additive (TS SDK 0.10.0-тэй ижил):

- **`SessionResult.Person`** (CA `person` блок: `FirstName`/`LastName`(эцгийн)/`FamilyName`(ургийн овог), `…En`,
  `CivilID`, `RegNo`, `BirthDate`, `Gender`, `GeID`), **`SessionResult.Raw`** (түүхий JSON), **`TokenCertificate`**
  блок; `PersonMatchesCertificate(person, subject)` — person блок гарын үсэгт ордоггүй тул `PNOMN-<civilId>` тулгалт.
- **`APIError` / `ForbiddenError`: `RetryAfter`** (Retry-After секунд эсвэл HTTP-огноо задалсан) **+ `Header`**;
  `APIError.Retryable()`, кодууд `CodePDFPrepareBusy`, `CodeDocumentPending`, `CodeTSAUnavailable`,
  `CodeLTVUnavailable`, `CodeRateLimited`, `CodeStateUnavailable`, `CodeIssuancePending` (`RetryableCodes`).
  **`Config.PDFTimeout`** (анхдагч `DefaultPDFTimeout` = 80s; өмнө нь тогтмол 60s).
- **`SignOptions.FileName`** → хүсэлтийн `fileName` (CA `NotificationSignRequest.FileName`).
- **`Client.Person`** (PKI_READ): `Certificates`, `Devices`, `Activity(ActivityQuery)`, `Summary`, `Children`.
  **`Client.Token`**: `IssueCertificate` (CA-ийн CSR hash тулгалттай), `CertificateResult`, `VerifyTokenCertificates`,
  `AuthChallenge`, `AuthVerify` (endResult + identity.etsi = гэрчилгээний SERIALNUMBER), `TokenAuthDigest` (TOKEN_AUTH
  тест вектор), `TokenLimitOf`.
- **Validator**: `TrustConfig.AllowedIssuerSKIs` (+ `CitizenIssuingCASKI`), `CheckKeyUsage` (auth → clientAuth,
  sign → nonRepudiation), `SchemeName`; `CheckRevocationStatus` → `good` / `unchecked` / `skipped` (+ алдаа).
- **PII**: `NetworkError.Op` замыг `/etsi/…`, `/document/…` болгож, `Err`-д `*url.Error`-ийн оронд шалтгааныг
  (бүтэн URL-гүй) хадгална; хариу задрахгүй алдааны зам мөн; гэрчилгээний хугацааны алдаа CN биш serial-аар.
- **`AuthenticationError`**: `Code`, `Message`, `Body`, `Header` (CA-ийн 401 vs proxy-ийн 401).
- Гэрээ: `routes.go`-д person ×5, token/certificate ×2; `/token/auth/*` CA-д байгаа ч discovery-д алга тул
  `rpRoutesUndiscovered` (гэрээний тест WARN).
- **Гэрээний шалгалт** (`go test -tags contract`, `.github/workflows/contract.yml` — PR / main / өдөр бүр): SDK-ийн
  RP-API зам бүр live `/.well-known/eid`-д, OIDC утгууд (issuer, ES256, S256, client_secret_basic, `Claims` талбарууд)
  `openid-configuration`-д таарахыг шалгана; SDK хамраагүй discovery замууд WARN. RP-API замууд `routes.go`-д нэг
  газар төвлөрсөн (зан төлөв өөрчлөгдөөгүй). Энгийн `go test` сүлжээгүй хэвээр.
- Шалгасан: `gofmt -l .`, `go vet ./...` (1.25 + 1.22), `go test -race ./...`, `go test -tags contract` (live).

## 0.1.1 — 2026-10-14

demo PDF device-link/push урсгалаас илэрсэн дутагдал — additive:

- **`ValidateSign(r, digest, hash, opts ...ValidateSignOptions)` — `ExpectedFlowType`** (additive: variadic, одоогийн
  дуудлагууд хэвээр хөрвөнө). Өгвөл хариуны `flowType` ЯГ таарах ёстой, эс бөгөөс `ValidateAuth`-тай ижил
  `*ValidationError` (`flowType X ≠ эхлүүлсэн урсгал Y (relay байж болзошгүй)`); нэгээс олон options → `*ValidationError`.
  Сонголтгүй / хоосон бол одоогийн зан. Яагаад: demo PDF device-link/push урсгалд flowType-ийг гараар тулгаж байсан
  (TS SDK 0.9.1-тэй ижил). RAW_DIGEST_SIGNATURE-д `flowType` гарын үсэгт ордоггүй — хариуны тулгалт.
- Шалгасан: `gofmt -l .`, `go vet ./...`, `go test -race ./...`.

## 0.1.0 — 2026-10-14

Анхны хувилбар — TypeScript SDK (`@gerege-systems/eid-mongolia-sdk` 0.8.1)-тэй функциональ ижил, Go idiom, зөвхөн
стандарт сан (Go ≥ 1.22).

- **RP-API client** (`eid.NewClient`): `Auth` (push `NotificationByEtsi/ByDocument`, device link
  `DeviceLinkAnonymous/ByEtsi`; `CallbackURL`, `OnBehalfOf`, алгоритм/hash сонголт), `Sign` (`DigestByEtsi/ByDocument`,
  `TextByEtsi`), `PDF` (PAdES `Prepare` multipart — `Digest` хоёр урсгалд (CA !332), `Interactions` device-link-д, `Document`), `Organization`
  (`GetRepresentations`), `Session` (`Poll`, `WaitForResult`), `ParseSessionResult`. Бүх дуудлага `context.Context`;
  Bearer secret, timeout, `HTTPClient` (mTLS). `ResolveBaseURL` — анхдагч `https://rp.eidmongolia.mn`, хуучин `ca.`
  хост тодорхой алдаа.
- **Төрөлжсөн алдаа** (`errors.As`): `AuthenticationError`, `ForbiddenError{Code}`, `APIError{Status,Body,Code}`,
  `NetworkError{Timeout}` (Unwrap), `SessionFailedError{EndResult}`, `ValidationError`, `DeviceLinkError`;
  `OnBehalfErrorCodes`.
- **Device link v3** (`BuildDeviceLink`, `TickQRDeviceLink`) — HMAC-SHA256 `authCode`, QR `elapsedSeconds`; CA-ийн 15
  golden вектортой байт-ижил. Legacy `/dl?sessionId&vc` оруулаагүй (сервер 2026-10-07-нд хассан).
- **Validator** — гинж (trust anchor = `NationalRootCAPEM`, issuer нэр + AKI/SKI + CA + гарын үсэг + хугацаа),
  хугацаа/`ClockSkew`, `RequiredLevel`, ACSP_V2 / prehashed digest гарын үсэг (`rsassa-pss`, `shaNNNWithRSAEncryption`,
  `ecdsa-with-SHA256` — зөвхөн EC P-256 + SHA-256, TS 0.9.0-тэй ижил), алгоритм ↔ түлхүүрийн төрөл тулгалт, `ExpectedFlowType` /
  `UserChallengeVerifier` (relay хаалт), `SignedCallbackURL`, `CheckRevocation` (OCSP/CRL hook, hard/soft-fail).
  Хариунд `Subject` (`ParseSubject`: GivenName, Surname, CommonName, SerialNumber, Country).
- `DocumentVerified` — татсан PDF-ийн SHA-256 = session-ий `pdf.outSha256` (READY).
- Крипто туслах: `SHA256Base64`, `RandomChallenge`, `InteractionsToBase64` (JS `JSON.stringify`-тай байт-ижил),
  `BuildACSPV2Payload`, `ACSPV2Digest`, `UserChallengeOf`, `VerifyPayloadSignature`, `VerifyPrehashedSignature`.
- **`oidc` багц** — «eID-ээр нэвтрэх»: `Discover` (1 цаг cache, issuer яг тулгалт), `CreateAuthorization`
  (state/nonce/PKCE S256, `Display`), `HandleCallback` (state constant-time, RFC 9207 `iss`, алдааны код, token солих
  `client_secret_basic` RFC 6749 §2.3.1), `VerifyIDToken` (ES256, JWKS cache + танихгүй `kid` нэг refetch, iss / aud /
  azp / exp / iat ±60с / nonce / sub), `Claims`, `PKCEChallenge`, `Error{Code,Description}`.
- Шалгасан: `go vet`, `go test -race` (Go 1.22 + stable CI), staticcheck; TS SDK 0.8.1-тэй санамсаргүй 300 device
  link, 60 ACSP payload/digest, 100 interactions байт-ижил, гарын үсэг хоёр чиглэлд verify.
