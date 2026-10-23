# Харагдах гарын үсэг — APPEARANCE_SPEC (pades-client/1)

Хэрэгжүүлэлт (reference): `pades/internal/core/appearance.go` (`AppearanceContent`, `AppearanceObjects`, `VisibleWidget`,
`VisibleRect`), `core/signature.go` (`PrepareSignatureVisible`), `pades/prepare.go` (`Appearance`), validator
`pades/internal/validate/appearance.go`. Native SDK бүр **байт-ижил** гаргана — golden `quartz-pdf13-visible`,
`quartz-pdf13-visible-en`, `quartz-pdf13-visible-second`, `quartz-pdf13-visible-twice`, `quartz-rotated90-visible`
(tag `pades-golden-v3`). Фонт, QR, бичвэрийн дүрэм нь [PAGE_SPEC.md](PAGE_SPEC.md)-тэй ижил (§2 фонт/glyph/өргөн, §7 QR).

`appearance` байхгүй (nil) бол гарын үсэг ҮЛ ХАРАГДАХ — PROFILE.md §2-тэй байт-ижил (v2 golden хэвээр).

## 1. Оролт ба байршил

```
appearance: { page: int (1-ээс; 0/байхгүй = оролтын eID verify хуудас БИШ сүүлийн хуудас — PLACEMENT_SPEC §1a), x, y, width, height: тоо (pt), lang: "mn"|"en", exact: bool (анхдагч false — PLACEMENT_SPEC §6a),
              signatureImage?, stampImage?: PDF зураг (§6, golden v10; width = height = 0 → анхдагч хэмжээ §6.3) }
```

- **h100** — бүх урт/координат 1/100 pt-ийн бүхэл тоо: `round100(v) = floor(v × 100 + 0.5)` (IEEE-754 double).
  Бичихдээ `num100(n)`: `n/100` бүхэл хэсэг (сөрөг бол `-` угтвар, абсолют утгаар), `n%100 ≠ 0` бол `.` + 2 орон, төгсгөлийн
  `0`-г хасна (`150 → 1.5`, `105 → 1.05`, `59528 → 595.28`, `-50 → -0.5`).
- Шалгалт (бүгд `REQUEST_INVALID`, PDF задлахаас өмнө): x, y, width, height нь хязгаартай (NaN/Inf биш), `0 ≤ v ≤ 14400`;
  `page ≥ 0`; `lang` ∈ {"", mn, en}; claimedRole-д `Cc`/`Cf` тэмдэгт байхгүй (validator-ийн `validClaimedRole`).
- `lang` хоосон бол `PrepareOptions.lang`, тэр нь хоосон бол `mn`.
- **page** нь Prepare-д ӨГСӨН баримтын хуудас (энэ Prepare-ийн нэмэх verify хуудас тооцогдохгүй). Тодорхой дугаар
  (1…N) өмнөх гарын үсгийн verify хуудас ч байж болно — юуг ч алгасахгүй. `0`/байхгүй бол өмнөх revision-уудын нэмсэн
  eID verify хуудсуудыг алгасаж, түүнээс өмнөх сүүлийн хуудас (PLACEMENT_SPEC §1a; golden v6-аас). Хуудасны тоо = `/Root /Pages` модыг `/Kids`-ээр дарааллаар тоолсон `/Type /Page`
  (гүн ≤ 32; `/Count`-д итгэхгүй). `page > тоо` → `REQUEST_INVALID`.
- **Байршил** ([PLACEMENT_SPEC.md](PLACEMENT_SPEC.md)): `x, y` нь хүссэн байрлал; хуудсан дээрх агуулга (бичвэр, зураг,
  зураас, annotation)-тай давхцвал дүрслэл тогтсон дарааллаар чөлөөт байрлал руу шилжинэ. Чөлөөтэй бол байт-ижил.
  `exact: true` (иргэн өөрөө байрлуулсан) бол хэзээ ч шилжихгүй — яг тэр тэгш өнцөгтөд, агуулгатай давхцвал
  `placement.status = "overlap"` (PLACEMENT_SPEC §6a). Гарын үсэггүйгээр санал болгох байрлал/хуудасны хэмжээ:
  `suggestPlacement` (PLACEMENT_SPEC §6b).
- **Хайрцаг**: хуудасны `/CropBox`, байхгүй бол `/MediaBox` — хоёулаа `/Parent`-ээр удамшина (гүн ≤ 32). 4 тоо (бүхэл/бодит),
  `round100`, хэвийн болгоно: `box = [min(x0,x2) min(y0,y2) max(x0,x2) max(y0,y2)]`. Алга/буруу → `REQUEST_INVALID`.
- **Эргэлт**: удамшсан `/Rotate` (бүхэл, 90-ийн үржвэр, эс бөгөөс `REQUEST_INVALID`), `rot = ((r mod 360) + 360) mod 360`.
- **Координатын орон зай**: x, y, width, height нь хуудсыг ДЭЛГЭЦЭНД харагдах байдлаар (`/Rotate`-ийн дараа) — эх нь харагдах
  зүүн доод булан, x баруун тийш, y дээш. `bw = box[2]−box[0]`, `bh = box[3]−box[1]`; харагдах хэмжээ `(vw, vh) = (bw, bh)`
  (rot 0/180) эсвэл `(bh, bw)` (90/270). `x + w ≤ vw`, `y + h ≤ vh`, `w > 0`, `h > 0` биш бол `REQUEST_INVALID`.
- Харагдах цэг `(vx, vy)` → хэрэглэгчийн орон зай `(ux, uy)`:

  | rot | ux | uy |
  |---|---|---|
  | 0 | `box[0] + vx` | `box[1] + vy` |
  | 90 | `box[2] − vy` | `box[1] + vx` |
  | 180 | `box[2] − vx` | `box[3] − vy` |
  | 270 | `box[0] + vy` | `box[3] − vx` |

  `/Rect = [min(ux1,ux2) min(uy1,uy2) max(ux1,ux2) max(uy1,uy2)]`, `(ux1,uy1) = f(x, y)`, `(ux2,uy2) = f(x+w, y+h)`.

## 2. Объектууд (R_sig — PROFILE.md §2-ийн өөрчлөлт)

Дугаар: `sigID, fieldID, catID` (PROFILE §2), дараа нь `formID, F1×5, F2×5` (нийт 11) дараалан reserve. Бичих дараалал: Sig толь,
widget, form, F1 (Type0, CIDFontType2, FontDescriptor, FontFile2, ToUnicode), F2 (мөн), хуудас (эсвэл түүний `/Annots`
массив), Catalog. Sig толь, Catalog нь PROFILE §2-той ижил; `/Name` ЗААВАЛ бичигдэх ёстой (PROFILE §2-ийн дүрмээр орхигдох
нэр бол `REQUEST_INVALID`) ба appearance-ийн нэр = `trim(/Name-ийн бичвэр)`.

Widget (`fieldID`) — үл харагдахын оронд, яг энэ байтаар:
```
<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [x1 y1 x2 y2]\n  /P <page> <gen> R\n  /F 4\n  /FT /Sig\n  /T (Signature k)\n  /V <sigID> 0 R\n  /AP << /N <formID> 0 R >>\n>>
```
(`/Rect` — §1, num100; `/P` ба `/Annots`-д нэмэх хуудас = `page`-ийн хуудас; `/F 4` = Print.) Widget-ийг тэр хуудасны
`/Annots`-ийн төгсгөлд PROFILE §2.3-ийн дүрмээр нэмнэ.

Form XObject (`formID`):
```
<< /Length n /Type /XObject /Subtype /Form /BBox [0 0 BW BH] /Resources << /Font << /F1 <F1> 0 R /F2 <F2> 0 R >> >> >>\nstream\n<§3>\nendstream
```
`(BW, BH) = (w, h)` (rot 0/180) эсвэл `(h, w)` (90/270) — `/Rect`-ийн хэмжээ. `/Matrix` БАЙХГҮЙ (PDFKit эргүүлсэн `/Matrix`-тэй
дүрслэлийг зурдаггүй); эргэлтийг content-ийн `cm` хийнэ. Фонтын 10 объект = PAGE_SPEC §8-ийн `<Type0> <CID> <fd> <ff> <tu>`
(NotoSans, дараа нь NotoSans-Bold) байт-ижил. Объект бүр ШИНЭ (verify хуудасны фонтыг дахин ашиглахгүй).

## 3. Content stream (шахалтгүй, мөр бүрийн ард LF; `W = w`, `H = h` — харагдах хэмжээ, h100)

Тогтмол (h100): `pad = 400`, `gap = 400`, `minModule = 100`; нэрийн фонт `f` = 11 → 7 (pt), бусад мөр `b = f − 2`;
мөрийн өндөр `size × 125`, суурь шугам мөрийн хайрцгийн доороос `size × 25`; нэр, үүрэг тус бүр ≤ 2 мөр.

1. `qr = QR(url)` (PAGE_SPEC §7, маск 0), `n` = модулийн тоо (url 71–72 байт → хувилбар 5, n = 37).
   `mod = floor((H − 2·pad) / n)`; `mod < minModule` → `REQUEST_INVALID` («хэт жижиг», өндөр ≥ 45 pt).
   `tx = pad + mod·n + gap`, `tw = W − tx − pad`.
2. Мөрүүд (f = 11, 10, … 7 — эхний таарсан):
   - нэр: PAGE_SPEC §4-ийн wrap (F2, f, `limit = tw × 10` [1/1000 pt], ≤ 2 мөр, илүү бол сүүлийнх «…»);
   - үүрэг (claimedRole хоосон биш бол): wrap (F1, b, ≤ 2 мөр);
   - label (F1, b): mn `eID Mongolia-аар зурсан`, en `Signed with eID Mongolia`;
   - огноо (F1, b): `YYYY-MM-DD HH:MM (+08)` — SigningTime (`/M`)-ийн +08:00 цаг. **TSA-ийн цаг биш**: prepare-ийн үед
     timestamp байхгүй (иргэн зурахаас өмнө дүрслэл тогтох ёстой); жинхэнэ цаг = timestamp (Adobe-ийн Signatures самбар / verify хуудас).
   Тохирох нөхцөл: мөр бүр хоосон биш ба `width1000(мөр) ≤ limit`, `Σ size × 125 ≤ H − 2·pad`. `tw ≤ 0` эсвэл аль ч f
   тохирохгүй → `REQUEST_INVALID` («хэт жижиг»).
3. Үйлдлүүд (дарааллаар; `cm` мөр зөвхөн rot ≠ 0 үед):
   ```
   /EIDVerify <</URL (<url>)>> BDC
   [q
   <cm>]                         rot 90: 0 1 -1 0 H 0 cm | 180: -1 0 0 -1 W H cm | 270: 0 -1 1 0 0 W cm
   0.086 0.541 0.31 RG
   1 w
   0.5 0.5 <W−100> <H−100> re S
   q <mod> 0 0 <mod> <pad> <floor((H − mod·n)/2)> cm
   0 0 0 rg
   <s> <n−1−r> <c−s> 1 re        мөр r (0 = дээд) бүрийн хар модулийн тасралтгүй хэсэг [s, c), мөр дээрээс доош, зүүнээс баруун
   f
   Q
   <өнгө> rg                     мөр бүрд (нэр, үүрэг — 0.118 0.118 0.118; label — 0.086 0.541 0.31; огноо — 0.431 0.431 0.431)
   BT /F<id> <size> Tf <tx> <y> Td <GGGG…> Tj ET
   [Q]
   EMC
   ```
   Тоо бүр num100 (QR-ийн `re` мөр модулийн нэгжээр бүхэл). `cursor = H − pad − floor((H − 2·pad − Σ size×125) / 2)`;
   мөр бүрд `cursor −= size × 125`, `y = cursor + size × 25`. `<GGGG…>` = PAGE_SPEC §2 (glyph ID %04X, cmap-д алга → `?`).
   `url = https://ca.eidmongolia.mn/verify/<docID>/<revIndex>` (revIndex = PRECHECKS #6; docID — verify хуудаснаас / opts;
   алга бол `REQUEST_INVALID`). BDC-ийн property list нь validator-д URL-ийг өгнө (viewer үл тооно).

Жишээ (`quartz-pdf13-visible-second`, 236 × 72 pt, 2 дахь гарын үсэг, onBehalfOf): `mod = 1.72`, `q 1.72 0 0 1.72 4 4.18 cm`,
`tx = 71.64`, мөрүүд F2 11 (48.75), F1 9 (37, 25.75, 14.5).

## 4. Хязгаар ба шийдвэр

- Фонтын хамгийн бага хэмжээ: нэр 7 pt, бусад 5 pt; QR модуль ≥ 1 pt (өндөр ≥ 45 pt). Дээш хэмжээ хязгааргүй (f ≤ 11).
- Арын дэвсгэр БҮРХЭХГҮЙ (тунгалаг) — RP хоосон хэсэг сонгоно. NoRotate туг үгүй — дүрслэл хуудастай хамт эргэнэ.
- PAGE_SPEC-ийн verify хуудастай тусдаа: `/Link` annotation нэмэхгүй (QR л).
- Хэмжээ: харагдах гарын үсэг бүр ~+90 KB (2 фонт шинээр).

## 5. Validator (own-signer профайл) — CA `server/internal/validate`-д 1:1 порт

`profileOwnSigner`-ийн R_sig алхамд (revisions.go `newField`, `c.own`) шинэ талбарын толь `/AP`-тэй бол **зөвхөн** доорх бүгд
биелбэл хүлээн авна (`ownVisible`); `/AP`-гүй бол хуучин дүрэм (үл харагдах: `/Rect [0 0 0 0]`, `/F 132`). Аль нэг нь унавал
`errNotSignatureOnly` → өмнөх гарын үсэг `modified_after_signing`.

1. Widget толины түлхүүр ⊆ {Type, Subtype, Rect, P, F, FT, T, V, AP}; `/P` ref нь эцсийн хуудасны модны `/Page`; `/V` ref;
   `/T` string; `/AP` ШУУД толь, ЯГ нэг түлхүүр `/N` (ref).
2. Хуудасны хайрцаг/эргэлт §1-ээр (`/Parent`-ээр удамшсан, round100); `/Rect`-ийн 4 тоо (бүхэл/бодит, |v| ≤ 1e7) round100;
   `x1 < x2`, `y1 < y2`, хайрцаг дотор. `w = x2−x1`, `h = y2−y1` (90/270 бол солино).
3. **Widget-ийн тэнцүү байдал**: `VisibleWidget(T, rect, P, sigID=/V, formID=/AP/N)`-ийг задалсан толь == бодит толь (бүтцээр:
   `pdfEqual` — бүхэл ≠ бодит, ref-ийг дугаараар). Тиймээс `/F 4`, `/FT /Sig`, `/Type`, `/Subtype` хатуу; `/A` `/AA` `/MK` `/DA`
   … үгүй.
4. Sig толь (`/V`): `/Name` string ЗААВАЛ; `/M` = `D:YYYYMMDDHHmmSS+08'00'` (өөр бүс → татгалзана); огноо = §3.
   claimedRole = CMS signedAttrs-ийн signer-attributes-v2 id-at-role утгууд (`claimedRoles`): 0 → "", яг 1 → тэр, > 1 → татгалзана.
5. **11 объектын дугаар**: `/N` → (stream) `/Resources /Font /F1`, `/F2` (ref) → Type0 `/DescendantFonts [ref]` (яг 1),
   `/ToUnicode` (ref) → CID `/FontDescriptor` (ref) → `/FontFile2` (ref). Дараалал `[N, F1: Type0, CID, FD, FF, TU, F2: …]`.
   Бүгд ШИНЭ (суурьт ашиглагдаагүй), үе 0, давхардалгүй.
6. Form stream-ийн түүхий байт `^/EIDVerify <</URL \(https://ca\.eidmongolia\.mn/verify/(<uuid жижиг>)/([1-9][0-9]?)\)>> BDC\n`-ээр
   эхэлнэ; `revIndex` = энэ гарын үсгийн дараалал (Extract-ийн задалсан гарын үсгүүдийг ByteRange[2]+[3]-аар эрэмбэлсэн, 1-ээс);
   баримтад verify хуудасны `/Link` (`/A /URI` = `https://ca.eidmongolia.mn/verify/<uuid>`, эхнийх) байвал uuid тэнцүү.
7. **Дахин үүсгэж тулгах**: `AppearanceObjects({W:w, H:h, Rotate, Name:/Name, Role, Date, URL, Lang})`-ийг lang ∈ {mn, en}
   тус бүрд үүсгэж, 11 объект бүрийн бие (задалсан толь + stream-ийн ТҮҮХИЙ байт) бодиттой `pdfEqual` — аль нэг хэлээр бүгд
   тэнцүү бол хүлээн авна. (Content stream, фонтын программ, ToUnicode, `/W`, BBox, нөөцийн толь — нэг ч байт зөрвөл татгалзана;
   `/Matrix`, `/XObject`, нэмэлт нөөц үгүй.)
8. `run()`: own харагдах widget нь `/P` хуудасныхаа `/Annots`-д (page()-ийн дүрмээр төгсгөлд) ЗААВАЛ орсон байна (өөр хуудасны
   `/Annots`-д эсвэл аль ч `/Annots`-д ороогүй → татгалзана). Strict алхамд шинэ объектын үүрэг ∈ {sig, field, catalog, xref
   stream өөрийн мөр} ∪ {ap — зөвхөн own харагдах widget шалгагдсан үед}. `c.visible` нь own харагдах widget-гүйгээр үнэн
   байвал татгалзана. /AP-ийн объектууд «ap» үүрэгтэй, зөвхөн дүрслэл дотроос заагдана (edges — хуучин дүрэм).
9. Тайлан: `visible_later_signature` (дараагийн харагдах гарын үсэг — хуучин талбар, одоо own-д үнэн болж болно) ба шинэ
   `visible` (ЭНЭ гарын үсгийн талбар — `/FT /Sig`, `/V` → энэ толь — `/AP`-тэй эсвэл `/Rect`-ийн өргөн, өндөр хоёулаа 0 биш).
   Мэдээллийн; indication-д нөлөөлөхгүй.
10. **ObjStm-ээс задлах** (revisions.go `diff`): хуучин объект ObjStm дотор (`entComp`) байсан ба шинэ хэсэгт ШУУД объект
    (`entUse`, үе 0) болж дахин бичигдсэн бол — own алхамд, эсвэл own-profile-ийн хуримтлагдсан (strict биш, DSS-only биш)
    шалгалтад — «хэлбэр солигдсон» гэж шууд татгалзахгүй; утга нь суурьтай ИЖИЛ бол татгалзана; бусад шаардлага нь хуучин
    `ownRewrite` дүрэм (өөрчлөгдсөн, зөвшөөрөгдсөн, үүрэг = page эсвэл annots). Шууд → ObjStm, үе солих — үргэлж татгалзана.
    Шалтгаан: олон хуудастай ObjStm баримтын 2+ хуудсанд дараагийн гарын үсгийн widget нэмэхэд бичигч тэр хуудсыг шууд
    объектоор бичдэг (эхний хуудсыг эхний гарын үсэг аль хэдийн задалсан байдаг тул үл харагдахад илрээгүй).

Тест (Go): `internal/validate/appearance_test.go` — хүлээн авах (харагдах × 2, 2-р хуудас ObjStm дотор) ба халдлага: widget `/A`,
`/AA`, `/F 6`, `/Rect` зөрүү, `/AP /D`, AP хуучин объект заана (`/XObject`), content stream өөрчлөлт/нэмэлт бичвэр, URL
revIndex/docID, `/Matrix`, фонтын тодорхойлолт, ToUnicode, өөр хуудасны `/Annots`, `/Annots`-гүй, ObjStm хуудсыг ижил утгаар,
ObjStm-ийн хуудас биш объектыг дахин бичих.

## 6. Гарын үсгийн ба байгууллагын тамганы зураг (golden v10)

Батлагдсан загвар (canvas A2 / B1, 2026-10-23). Зураг нь **widget-ийн `/AP /N` form дотор** (Sig-тэй нэг incremental
update) — тусдаа `/Stamp` annotation БИШ: Adobe тусдаа annotation-ийг «Annotations Created», pyHanko `OTHER` гэж үздэг;
form дотор бол Adobe «not modified», pyHanko `FORM_FILLING` (2026-10-23 туршсан). Зураггүй (`signatureImage`,
`stampImage` хоёулаа байхгүй) бол §1–§5 хэвээр, **golden v9-тэй байт-ижил**.

### 6.1 Оролт — «PDF зураг» (CA-ийн өгөх хэлбэр)

```
appearance.signatureImage | appearance.stampImage:
  { width: int, height: int,          // px, 1…1600
    color: [r, g, b],                 // бэхний ганц өнгө, 0…255
    alpha: "<base64>",                // zlib (RFC 1950) stream → яг width·height байт, мөр дээрээс доош, PNG filter байтгүй
    sha256: "<64 жижиг hex>" }        // CA-ийн хадгалсан PNG-ийн sha256 (PDF-д бичигдэхгүй — §6.6)
```

SDK оролтыг PNG-ээр АВАХГҮЙ: PNG-ийн IDAT-ийг дахин шахах нь хэл бүрт өөр байт гаргана. CA PNG-ээс alpha-г гаргаж нэг
удаа шахна; SDK `alpha`-г **байтаар нь** /SMask stream болгон бичнэ (runtime шахалт үгүй — бүх SDK байт-ижил).

Шалгалт (бүгд `REQUEST_INVALID`, PDF задлахаас өмнө; `suggestPlacement`-д ч): `1 ≤ width, height ≤ 1600`; өнгө бүр
0…255; `1 ≤ len(alpha) ≤ 300 KiB` (307 200 байт); alpha нь НЭГ zlib stream — preset dictionary (FDICT) үгүй, Adler-32 зөв,
stream-ийн ард илүү байт үгүй, задлахад яг `width·height` байт; `sha256` нь `^[0-9a-f]{64}$`. `stampImage` нь зөвхөн
`claimedRole` (onBehalfOf)-той (Prepare-д; `suggestPlacement` claimedRole-гүй тул шалгахгүй). Тамга гарын үсгийн зураггүйгээр
зөвшөөрөгдөнө — тэр үед B1-ийн геометр, дээд зурвас хоосон (зөвхөн хуваах шугам ба тамга).

### 6.2 Объектууд

Дугаар: §2-ийн 11 объектын ард зураг бүрд 2 — `[form, F1 ×5, F2 ×5, (Sig base, Sig mask), (Stamp base, Stamp mask)]`
(байгаа зураг л, энэ дарааллаар). Бичих дараалал ижил. Form-ийн нөөц:

```
/Resources << /Font << /F1 <F1> 0 R /F2 <F2> 0 R >> /XObject << /Sig <base> 0 R /Stamp <base> 0 R >> >>
```

(`/XObject` зөвхөн зурагтай үед, түлхүүр нь байгаа зургийнх.) Зураг бүр (`<<` дараах түлхүүрийн дараалал яг ийм, §2-ийн
`streamObj` хэлбэр — `/Length` эхэнд):

```
base: << /Length 3 /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8 /SMask <mask> 0 R >>\nstream\n<r g b — 3 байт>\nendstream
mask: << /Length n /Type /XObject /Subtype /Image /Width w /Height h /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode >>\nstream\n<alpha — оролтын байт>\nendstream
```

1×1 base + w×h /SMask: ISO 32000-1 §11.6.5.3 — mask ба зургийн нягтрал ялгаатай байж болно (хоёулаа нэгж дөрвөлжинд
буулгагдана). Рендер шалгасан (2026-10-23): PDFKit/Preview (`qlmanage`), pdfium (Chrome), pdf.js 4.10, MuPDF — бүгд зөв;
Adobe — хэрэглэгчийн гар шалгалт. /Interpolate, /Decode, /Matte үгүй.

### 6.3 Геометр (h100, харагдах орон зай; бүх хуваалт — сөрөг биш бүхэлд floor)

`W, H` = widget-ийн харагдах хэмжээ (`width`, `height`) — тамгатай үед хайрцаг **дээр нь тамганы гарах хэсэг** орсон
**нэгдэл**: `/Rect`, form `/BBox`, байршлын давхцал (PLACEMENT_SPEC) бүгд энэ нэгдлээр. Ногоон хүрээ form дотор хайрцгийн
байрлалд зурагдана.

`width = height = 0` (хоёулаа) бол анхдагч хэмжээ (`suggestPlacement`-д ч): зураггүй **220 × 64**, гарын үсгийн зурагтай
**220 × 110**, тамгатай (гарын үсэгтэй/үгүй) **240 × 147.5** (хайрцаг 240 × 118 + дээш 29.5). Аль нэг нь 0 биш бол өгсөн
утга (0 нь хэвээр `REQUEST_INVALID`).

| | A2 — гарын үсэг (тамгагүй) | B1 — тамгатай |
|---|---|---|
| хайрцгийн өндөр `boxH` | `H` | `H·4/5` |
| дээд зурвас `band` | `boxH·9/22` | `boxH·9/22` |
| QR/бичвэрийн мөр `rowH` | `boxH − band` | `boxH − band` |
| гарын үсгийн муж `sx, sw` | `sx = (W − W·15/22)/2`, `sw = W·15/22` | `sx = W/30`, `sw = qx + D/2 − sx` |
| муж `sy, sh` | `sh = band·14/15`, `sy = rowH − band·2/15` | ижил |
| гарын үсэг (fit-contain) | хэвтээ голлуулна: `dx = sx + (sw − dw)/2` | зүүн тийш: `dx = sx` |
| босоо | `dy = sy + (sh − dh)/2` | ижил |
| тамга | — | `D = boxH·2/3`, `qx = min(W·41/60 − D/2, W − D)`, `qy = H − D`; fit-contain `D × D` дотор, хоёр тэнхлэгт голлуулна: `dx = qx + (D − dw)/2`, `dy = qy + (D − dh)/2` |

**fit-contain** (`iw × ih` px → `bw × bh`): `iw·bh ≥ ih·bw` бол `dw = bw`, `dh = max(1, bw·ih/iw)`, эс бөгөөс
`dh = bh`, `dw = max(1, bh·iw/ih)` (үржвэр 64 бит — ≤ 1 440 000 · 1600). Гарын үсгийн муж хуваах шугамаас `band·2/15`
доош (≈ 6 pt) орно — бэх шугамыг давж болно (батлагдсан загвар). `qy = H − D` тул тамганы дээд ирмэг = нэгдлийн дээд ирмэг
(анхдагчид хайрцгийн дээд ирмэгээс 29.5 pt дээш, төв нь хайрцгийн дээд ирмэгээс 9.83 pt доош, зүүнээс 164 pt).
`qx < 0`, `D ≤ 0`, (гарын үсэгтэй) `sw ≤ 0` эсвэл `sh ≤ 0` → `REQUEST_INVALID` («хэт жижиг»). QR/бичвэр нь §3-ийн дүрмээр
**`H`-ийн оронд `rowH`-ээр**: `mod = floor((rowH − 2·pad)/n)`, QR-ийн `y = floor((rowH − mod·n)/2)`, `Σ size×125 ≤ rowH − 2·pad`,
`cursor = rowH − pad − floor((rowH − 2·pad − Σ)/2)`.

Анхдагч утгууд: A2 220×110 → `band 45`, `rowH 65`, муж `[40, 59] 150 × 42`, QR mod 1.54; B1 240×147.5 → `boxH 118`,
`band 48.27`, `rowH 69.73`, муж `[8, 63.3] 156 × 45.05`, `D 78.66`, тамга `[124.67, 68.84]`, QR mod 1.66.

### 6.4 Content stream (§3-ийн дараалал; зөрүүтэй мөрүүд л)

```
/EIDVerify <</URL (…)>> BDC
[q / <cm>]
0.086 0.541 0.31 RG
1 w
0.5 0.5 <W−100> <boxH−100> re S
0.5 w                                    ← зурагтай үед
0 <rowH> m <W> <rowH> l S                ← хуваах шугам (ногоон)
q <dw> 0 0 <dh> <dx> <dy> cm /Sig Do Q   ← гарын үсгийн зурагтай үед
q <mod> 0 0 <mod> <pad> <floor((rowH − mod·n)/2)> cm … Q    (QR)
<мөрүүд>
q <dw> 0 0 <dh> <dx> <dy> cm /Stamp Do Q ← тамгатай үед, ХАМГИЙН ДЭЭР (бусдыг дарж зурна)
[Q]
EMC
```

Жишээ `img-second` (240 × 147.5): `0.5 0.5 239 117 re S`, `0 69.73 m 240 69.73 l S`, `q 150.16 0 0 45.05 8 63.3 cm /Sig Do Q`,
`q 1.66 0 0 1.66 4 4.15 cm`, `q 78.66 0 0 78.66 124.67 68.84 cm /Stamp Do Q`.

### 6.5 Validator (§5-ын нэмэлт)

5-р алхамд `/Resources /XObject` (байвал ШУУД толь) нь `/Sig` ба/эсвэл `/Stamp` (ref) → base stream (өгөгдөл яг 3 байт,
`/SMask` ref) → mask stream (`/Width`, `/Height` бүхэл 1…1600). Дугаарын жагсаалт `[N, F1…, F2…, Sig base, Sig mask, Stamp base,
Stamp mask]` — бүгд шинэ, үе 0, давхардалгүй. 7-р алхамд `AppearanceParams`-д PDF-ээс уншсан зураг (`color` = base-ийн 3 байт,
`W/H` = mask-ийн, `alpha` = mask stream-ийн ТҮҮХИЙ байт) өгч дахин үүсгэнэ — §6.1-ийн alpha шалгалт (zlib, яг `w·h`) ажиллана;
объект бүр (base/mask-ийн толь, content stream-ийн `cm` байрлал — хэмжээнээс тооцсон) `pdfEqual`. Тамгатай боловч claimedRole
алга → татгалзана. Өнгө ба alpha-ийн агуулга нь оролт (PDF-ээс уншина) — өөр өнгө = өөр хүчинтэй зураг (энэ revision-ийн
гарын үсэгт хамрагдана); харин хэлбэр, хэмжээ, байрлал, нэмэлт түлхүүр/нөөц зөрвөл `modified_after_signing`.
Тест: `internal/validate/appearance_test.go` `TestOwnVisibleSignatureImages`.

### 6.6 Бүртгэл

PDF нь PNG-ийн sha256-г агуулахгүй. `Completed.images` = `[{kind: "signature"|"stamp", sha256}]` (signatureImage, дараа нь
stampImage — байгаа нь), `registration()` үүнийг POST /v3/pdf/signatures-д `images` болгон илгээнэ (зураггүй бол талбаргүй).
CA зурагчийн / байгууллагын (onBehalfOf) хадгалсан PNG-ийн sha256-тай тулгана. **CA тал хэрэгжээгүй** (2026-10-23): CA
`DisallowUnknownFields` тул `images` хүлээн авахаас өмнө зурагтай бүртгэл 400 болно.
