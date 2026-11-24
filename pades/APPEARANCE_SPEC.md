# Харагдах гарын үсэг — APPEARANCE_SPEC (pades-client/1)

Хэрэгжүүлэлт (reference): `pades/internal/core/appearance.go` (`AppearanceContent`, `AppearanceObjects`, `VisibleWidget`,
`VisibleRect`), `core/signature.go` (`PrepareSignatureVisible`), `pades/prepare.go` (`Appearance`), validator
`pades/internal/validate/appearance.go`. Native SDK бүр **байт-ижил** гаргана — golden `quartz-pdf13-visible`,
`quartz-pdf13-visible-en`, `quartz-pdf13-visible-second`, `quartz-pdf13-visible-twice`, `quartz-rotated90-visible`
(tag `pades-golden-v3`). Фонт, QR, бичвэрийн дүрэм нь [PAGE_SPEC.md](PAGE_SPEC.md)-тэй ижил (§2 фонт/glyph/өргөн, §7 QR).

`appearance` байхгүй (nil) бол гарын үсэг ҮЛ ХАРАГДАХ — PROFILE.md §2-тэй байт-ижил (v2 golden хэвээр).

**Хоёр хувилбар** (golden v12-аас): гарын үсэг зурагчийн гэрчилгээ e-Seal бол байгууллагын **тамганы дардас** (§6 —
QR/холбоосгүй, «eID Mongolia-аар тамгалсан»), бусад бүх гэрчилгээнд иргэний дардас (§3, өөрчлөгдөөгүй). Хувилбарыг ЗӨВХӨН
гэрчилгээ сонгоно (§6.1).

## 1. Оролт ба байршил

```
appearance: { page: int (1-ээс; 0/байхгүй = оролтын eID verify хуудас БИШ сүүлийн хуудас — PLACEMENT_SPEC §1a), x, y, width, height: тоо (pt), lang: "mn"|"en", exact: bool (анхдагч false — PLACEMENT_SPEC §6a) }
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

## 6. Seal stamp (organisation e-Seal) — golden v12

An organisation e-Seal signature (`pades.SealPDF`, or `prepare` with an e-Seal `signerCert`) draws the **seal stamp**
instead of the citizen stamp of §3. Everything not stated in this section is exactly §1–§5 (input checks, h100, `/Rect`,
rotation, the 11 objects and their order, widget bytes, form dictionary, fonts, placement — PLACEMENT_SPEC is unchanged
and does not depend on the variant).

### 6.1 Variant selection — by the signer certificate only

The variant is a pure function of the signer certificate (the CMS SignerInfo's certificate = `signerCert`); nothing in
the PDF or the options selects it. The certificate is an **e-Seal certificate** iff all of:

1. `basicConstraints` is absent or has `cA = FALSE`;
2. the `keyUsage` extension is present, bit 1 (`nonRepudiation` / `contentCommitment`) is **set** and bit 0
   (`digitalSignature`) is **clear** (other bits are ignored);
3. there is **no** `extendedKeyUsage` extension.

(= Go `eid.IsSealCertificate` = validator `sealCertificate`; the citizen SIGN certificate has `digitalSignature` set, so
it is never an e-Seal certificate.) A certificate that cannot be parsed is not an e-Seal certificate. e-Seal certificate
→ seal stamp (§6.2); any other certificate → citizen stamp (§3), byte-identical to golden v3–v9.
The stamp variant follows this rule only, and may differ from the validator's `certificate.usage` label: a certificate
with keyUsage = nonRepudiation only plus an extendedKeyUsage extension of unrecognised purposes is labelled `"seal"` by
the usage classifier but is **not** an e-Seal certificate here, so it draws (and is validated against) the citizen stamp.

### 6.2 Content stream (uncompressed, LF after every line; `W = w`, `H = h`)

No QR, no `/EIDVerify` marked content, no URL, no role line. Constants as §3 (`pad = 400`, name font `f` = 11 → 7, body
`b = f − 2`, leading `size × 125`, descent `size × 25`, name ≤ 2 lines).

1. `tx = pad`, `tw = W − 2·pad` (the text uses the full inner width — there is no QR column).
2. Lines (f = 11, 10, … 7 — the first that fits), in this order:
   - name: PAGE_SPEC §4 wrap (F2, f, `limit = tw × 10`, ≤ 2 lines, «…» on overflow) — `trim(/Name)`; SealPDF writes the
     certificate's GIVENNAME SURNAME, else its CN (the organisation name), unless `signerName` is given;
   - label (F1, b): mn `eID Mongolia-аар тамгалсан`, en `Sealed with eID Mongolia` (the citizen label with the verb
     changed; same colour and position as the citizen label line);
   - date (F1, b): `YYYY-MM-DD HH:MM (+08)` from `/M`, exactly as §3.
   A claimedRole in the CMS is **not** drawn. Fit rule as §3: every line non-empty, `width1000(line) ≤ limit`,
   `Σ size × 125 ≤ H − 2·pad`; `tw ≤ 0` or no f fits → `REQUEST_INVALID`. There is no QR-module minimum (a 220 × 64 pt
   stamp fits at f = 11; the smallest height that fits a one-line name is 29.25 pt).
3. Operations (in this order; the `q` / `cm` / `Q` lines only when rot ≠ 0, with the same `cm` as §3):
   ```
   [q
   <cm>]
   0.086 0.541 0.31 RG
   1 w
   0.5 0.5 <W−100> <H−100> re S
   <colour> rg                   per line (name 0.118 0.118 0.118; label 0.086 0.541 0.31; date 0.431 0.431 0.431)
   BT /F<id> <size> Tf <pad> <y> Td <GGGG…> Tj ET
   [Q]
   ```
   `cursor = H − pad − floor((H − 2·pad − Σ size×125) / 2)`; per line `cursor −= size × 125`, `y = cursor + size × 25`.
   Numbers num100; `<GGGG…>` = PAGE_SPEC §2. The form XObject dictionary is §2's, with both `/F1` and `/F2` (both are
   used: F2 name, F1 label/date).

Example (golden `seal-visible`, 220 × 64 pt, `TEST ONLY Golden Org LLC`, mn): f = 11, lines F2 11 / F1 9 / F1 9, text at x = 4.

### 6.3 Validator (own-signer profile) — changes to §5

The variant is chosen from the signature's certificate by §6.1 (`sigMeta.seal`, computed in Extract from the CMS leaf):

- **Not an e-Seal certificate** → §5 unchanged (citizen stamp; the form must start with the `/EIDVerify` BDC line).
- **e-Seal certificate** → §5 steps 1–5 and 8–10 unchanged; step 6 is **skipped** (no BDC / URL / revIndex / docId check —
  the seal stamp has none); step 7 regenerates `AppearanceObjects({W, H, Rotate, Name: /Name, Date, Lang, seal})` (no
  Role, no URL) for `lang ∈ {mn, en}` and requires all 11 objects to be equal for one language.
- Fail closed: a citizen certificate whose revision carries a seal stamp, and an e-Seal certificate whose revision
  carries a citizen stamp, do not match → `errNotSignatureOnly` → every earlier signature `modified_after_signing`
  (golden validate cases `seal-stamp-citizen-cert`, `citizen-stamp-seal-cert`). The broad (test-only) profile does not
  regenerate stamps and is unchanged.
- **Compatibility:** validators that implement only §5 (CA `/v3/validate/pdf` and the TS SDK before their seal-stamp
  release) report a revision with a seal stamp as a modification of every earlier signature. Writers must not emit
  the seal stamp to relying parties until those validators implement §6.3.

### 6.4 SealPDF default (Go `pades.SealOptions`)

- `invisible: true` → the invisible signature of PROFILE.md §2 (byte-identical to SealPDF before golden v12).
- `appearance` given → used as is (§1, PLACEMENT_SPEC; `exact` honoured); an invalid one is `REQUEST_INVALID`.
- neither → automatic. The page is resolved once: `s = suggestPlacement(pdf, {width: 1, height: 1})` (PLACEMENT_SPEC
  §1a/§6b: the last page that is not an eID verify page); `page = s.page` is then passed explicitly. With `pw, ph` =
  `s.pageWidth, s.pageHeight` (pt): `w = min(220, pw − 8)`, `h = min(64, ph − 8)`, `x = pw − w − min(36, (pw − w)/2)`,
  `y = min(36, (ph − h)/2)`, `exact = false` → PLACEMENT_SPEC §6 (free → requested; else the first free candidate →
  moved; none → overlap at the requested bottom-right). On a Letter/A4 page this is 220 × 64 at `(pw − 256, 36)`.
  If `suggestPlacement` fails, `w ≤ 0` or `h ≤ 0`, or `prepare` rejects the automatic stamp with `REQUEST_INVALID`
  (e.g. the text does not fit, §6.2), the seal is written **invisible** instead (`Completed.placement` = null); the
  caller asked for nothing, so the old invisible result is the fallback rather than an error. The same fallback applies
  when the automatic stamp's fonts (~82 KB) push the prepared file over the size limit (`PDF_TOO_LARGE`); an explicit
  `appearance` still returns `REQUEST_INVALID` / `PDF_TOO_LARGE`.
- The result is `Completed.placement` (null when invisible).
