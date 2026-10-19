# Харагдах гарын үсэг — APPEARANCE_SPEC (pades-client/1)

Хэрэгжүүлэлт (reference): `pades/internal/core/appearance.go` (`AppearanceContent`, `AppearanceObjects`, `VisibleWidget`,
`VisibleRect`), `core/signature.go` (`PrepareSignatureVisible`), `pades/prepare.go` (`Appearance`), validator
`pades/internal/validate/appearance.go`. Native SDK бүр **байт-ижил** гаргана — golden `quartz-pdf13-visible`,
`quartz-pdf13-visible-en`, `quartz-pdf13-visible-second`, `quartz-pdf13-visible-twice`, `quartz-rotated90-visible`
(tag `pades-golden-v3`). Фонт, QR, бичвэрийн дүрэм нь [PAGE_SPEC.md](PAGE_SPEC.md)-тэй ижил (§2 фонт/glyph/өргөн, §7 QR).

`appearance` байхгүй (nil) бол гарын үсэг ҮЛ ХАРАГДАХ — PROFILE.md §2-тэй байт-ижил (v2 golden хэвээр).

## 1. Оролт ба байршил

```
appearance: { page: int (1-ээс; 0/байхгүй = оролтын СҮҮЛИЙН хуудас), x, y, width, height: тоо (pt), lang: "mn"|"en" }
```

- **h100** — бүх урт/координат 1/100 pt-ийн бүхэл тоо: `round100(v) = floor(v × 100 + 0.5)` (IEEE-754 double).
  Бичихдээ `num100(n)`: `n/100` бүхэл хэсэг (сөрөг бол `-` угтвар, абсолют утгаар), `n%100 ≠ 0` бол `.` + 2 орон, төгсгөлийн
  `0`-г хасна (`150 → 1.5`, `105 → 1.05`, `59528 → 595.28`, `-50 → -0.5`).
- Шалгалт (бүгд `REQUEST_INVALID`, PDF задлахаас өмнө): x, y, width, height нь хязгаартай (NaN/Inf биш), `0 ≤ v ≤ 14400`;
  `page ≥ 0`; `lang` ∈ {"", mn, en}; claimedRole-д `Cc`/`Cf` тэмдэгт байхгүй (validator-ийн `validClaimedRole`).
- `lang` хоосон бол `PrepareOptions.lang`, тэр нь хоосон бол `mn`.
- **page** нь Prepare-д ӨГСӨН баримтын хуудас (энэ Prepare-ийн нэмэх verify хуудас тооцогдохгүй; өмнөх гарын үсгийн
  verify хуудас бол энгийн хуудас). Хуудасны тоо = `/Root /Pages` модыг `/Kids`-ээр дарааллаар тоолсон `/Type /Page`
  (гүн ≤ 32; `/Count`-д итгэхгүй). `page > тоо` → `REQUEST_INVALID`.
- **Байршил** ([PLACEMENT_SPEC.md](PLACEMENT_SPEC.md)): `x, y` нь хүссэн байрлал; хуудсан дээрх агуулга (бичвэр, зураг,
  зураас, annotation)-тай давхцвал дүрслэл тогтсон дарааллаар чөлөөт байрлал руу шилжинэ. Чөлөөтэй бол байт-ижил.
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
