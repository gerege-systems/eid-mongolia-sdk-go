# Харагдах гарын үсэг — APPEARANCE_SPEC (pades-client/1)

Хэрэгжүүлэлт (reference): `pades/internal/core/appearance.go` (`AppearanceContent`, `AppearanceObjects`, `VisibleWidget`,
`VisibleRect`), `core/signature.go` (`PrepareSignatureVisible`), `pades/prepare.go` (`Appearance`), validator
`pades/internal/validate/appearance.go`. Native SDK бүр **байт-ижил** гаргана — golden `quartz-pdf13-visible`,
`quartz-pdf13-visible-en`, `quartz-pdf13-visible-second`, `quartz-pdf13-visible-twice`, `quartz-rotated90-visible`
(tag `pades-golden-v3`). Фонт, QR, бичвэрийн дүрэм нь [PAGE_SPEC.md](PAGE_SPEC.md)-тэй ижил (§2 фонт/glyph/өргөн, §7 QR).

`appearance` байхгүй (nil) бол гарын үсэг ҮЛ ХАРАГДАХ — PROFILE.md §2-тэй байт-ижил (v2 golden хэвээр).

**Гурван хувилбар**: иргэний дардас (§3) — e-Seal биш бүх гэрчилгээнд; e-Seal гэрчилгээнд байгууллагын **тамганы
дардас** — QR-гүй (§6.2, golden v12, «eID Mongolia-аар тамгалсан») эсвэл QR-тэй (§6.5, golden v13 — иргэний дардасны бүтэц,
тамганы label). Иргэний/тамганы хувилбарыг ЗӨВХӨН гэрчилгээ сонгоно (§6.1); тамга QR-тэй эсэхийг бичигч сонгоно, validator
form stream-ийн `/EIDVerify` тэмдгээр таньна (§6.3). Prepare-ийн docId-ийн дүрэм — §6.6.

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
   `url = https://ca.eidmongolia.mn/verify/<docID>/<revIndex>` (revIndex = PRECHECKS #6; docID — §6.6). BDC-ийн property
   list нь validator-д URL-ийг өгнө (viewer үл тооно).

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

## 6. Seal stamp (organisation e-Seal) — golden v12, v13

An organisation e-Seal signature (`pades.SealPDF`, or `prepare` with an e-Seal `signerCert`) draws a **seal stamp**
instead of the citizen stamp of §3: the QR-less seal stamp (§6.2, golden v12) or the seal stamp with QR (§6.5, golden
v13). Everything not stated in this section is exactly §1–§5 (input checks, h100, `/Rect`, rotation, the 11 objects and
their order, widget bytes, form dictionary, fonts, placement — PLACEMENT_SPEC is unchanged and does not depend on the
variant).

### 6.1 Variant selection — by the signer certificate only

The variant is a pure function of the signer certificate (the CMS SignerInfo's certificate = `signerCert`); nothing in
the PDF or the options selects it. The certificate is an **e-Seal certificate** iff all of:

1. `basicConstraints` is absent or has `cA = FALSE`;
2. the `keyUsage` extension is present, bit 1 (`nonRepudiation` / `contentCommitment`) is **set** and bit 0
   (`digitalSignature`) is **clear** (other bits are ignored);
3. there are **no** EKU purposes (the `extendedKeyUsage` extension is absent or empty).

(= Go `eid.IsSealCertificate` = validator `sealCertificate`; the citizen SIGN certificate has `digitalSignature` set, so
it is never an e-Seal certificate.) A certificate that cannot be parsed is not an e-Seal certificate. e-Seal certificate
→ seal stamp (§6.2 or §6.5); any other certificate → citizen stamp (§3), byte-identical to golden v3–v9. Whether a seal
stamp carries a QR is the writer's choice (§6.5 «Writers»), never a function of the certificate; a validator recognises
it by the marker (§6.3).
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

The certificate variant is chosen from the signature's certificate by §6.1 (`sigMeta.seal`, computed in Extract from
the CMS leaf). Let `data` be the form XObject's stream data **as stored**: exactly the `/Length` bytes that follow
`stream` + EOL (never a scan to `endstream`), not decoded whatever `/Filter` says — eID writers never set a filter, and a
`/Filter` entry anywhere in the form dictionary already fails step 7 (the regenerated dictionary has none). §5 step 6
reads the same bytes.

- **Not an e-Seal certificate** → §5 unchanged (citizen stamp; `data` must start with the `/EIDVerify` BDC line; Role =
  the CMS claimedRole).
- **e-Seal certificate, `data` begins with the 10 bytes `/EIDVerify`** → **QR seal stamp** (§6.5, golden v13): §5 steps
  1–10 all apply. Step 6 in full: `data` must match the step-6 regex at offset 0, its `<rev>` must equal this
  signature's revIndex, and when the document has a verify-page link its `<uuid>` must equal that link's docId. Step 7
  regenerates `AppearanceObjects({W, H, Rotate, Name: /Name, Date, URL: https://ca.eidmongolia.mn/verify/<uuid>/<rev>
  (from the marker), Lang, seal, Role: ""})` for `lang ∈ {mn, en}` — the CMS claimedRole is **ignored** (step 4 still
  requires 0 or exactly 1 claimedRole value), so a stamp that draws a role line does not match.
- **e-Seal certificate, `data` does not begin with `/EIDVerify`** → **QR-less seal stamp** (§6.2, golden v12): step 6 is
  skipped (no URL / revIndex / docId check — the stamp has none); step 7 regenerates `AppearanceObjects({W, H, Rotate,
  Name: /Name, Date, Lang, seal})` (no Role, no URL).
- In both seal cases all 11 objects must be equal for one language. **The marker decides; there is no fallback**: a
  stream that starts with `/EIDVerify` is checked only as the QR seal stamp and one that does not only as the QR-less
  stamp — a failure is never retried as the other variant.
- Fail closed: any mismatch → `errNotSignatureOnly` → every earlier signature `modified_after_signing`. Golden validate
  negatives (each a second B-B signature on `golden/output/quartz-pdf13.pdf`): v12 `seal-stamp-citizen-cert` (citizen
  certificate + QR-less seal stamp), `citizen-stamp-seal-cert` (e-Seal certificate + citizen stamp — the marker sends it
  to the QR seal path, where the label differs); v13 `seal-qr-citizen-cert` (citizen certificate + QR seal stamp),
  `seal-qr-with-role` (e-Seal certificate, CMS claimedRole, QR seal stamp drawn with the role line), `seal-qr-wrong-rev`
  (marker `…/3` on signature 2), `seal-qr-docid-vs-page` (marker docId ≠ the verify-page docId),
  `seal-v12-with-marker` (the correct marker line, then the QR-less seal content, then `EMC`), `seal-qr-height-44pt`
  (a 220 × 44 pt QR seal stamp drawn with 0.97 pt modules — §6.5 requires ≥ 45 pt), `seal-marker-not-at-start` (a
  QR-less seal stream with the marker line after its first line → QR-less path, mismatch), `seal-qr-flate` (the QR seal
  stream FlateDecode-compressed with `/Filter /FlateDecode` → `data` does not start with the marker, QR-less path,
  mismatch), `seal-qr-marker-crlf` (`BDC\r\n`), `seal-qr-uuid-uppercase` (uppercase uuid, on a document without a verify
  page), `seal-qr-rev-02` (rev written `02`). Each negative differs in one field from a passing control built by the
  same generator: `seal-qr-control` (on `quartz-pdf13`), `seal-qr-control-nopage` (on `quartz-pdf13-nopage`, for the
  uppercase case). The broad (test-only) profile does not regenerate stamps and is unchanged.
- **Not tightened:** the docIds of different stamps are **not** compared with each other — only each stamp's marker
  against the verify-page link, when the document has one. Two stamps carrying different docIds (a citizen with a
  caller-supplied docId after a QR-less seal; files from writers before §6.6) are not tampering: each QR leads to its
  own signer's record. Golden validate positive `sealv12-then-citizen`; Go test `TestOwnVisibleSealQR`.
- **Compatibility:** validators that implement only §5 (CA `/v3/validate/pdf` and the TS SDK before their seal-stamp
  release) report a revision with any seal stamp as a modification of every earlier signature; validators that
  implement the v12 version of this section (QR-less only) do the same for a QR seal stamp. Writers must not emit the
  QR-less seal stamp until validators implement §6.3 (v12), and **must not emit the QR seal stamp until the CA and TS
  validators implement this version (§6.5)**.

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
- The stamp is always the QR-less seal stamp (§6.2): `SealPDF` has no option for §6.5 in this release, and its output is
  byte-identical to golden v12 (`seal-visible`, `seal-visible-en` DTBS — Go test `TestSealPDFStillQRless`).

### 6.5 Seal stamp with QR — golden v13

The QR seal stamp is the **citizen stamp of §3** with exactly three differences:

1. **Label**: the seal label of §6.2 — mn `eID Mongolia-аар тамгалсан`, en `Sealed with eID Mongolia` (F1, size `b`,
   colour `0.086 0.541 0.31`, in the label line's place).
2. **No role line, ever**: §3 step 2 runs with role = "" even when the CMS carries a claimedRole (whatever the caller
   passes as `claimedRole`; the claimedRole itself still goes into signedAttrs as usual).
3. **Name** = `trim(/Name)` as in §6.2 (SealPDF: the certificate's GIVENNAME SURNAME, else its CN, unless `signerName`).

Everything else is §3 byte for byte: `url = https://ca.eidmongolia.mn/verify/<docId>/<rev>` (`<rev>` = PRECHECKS #6 — the
signature's position in the file; `<docId>` = §6.6); `qr = QR(url)` (PAGE_SPEC §7, mask 0); `mod = floor((H − 2·pad) / n)`,
`mod < 100` → `REQUEST_INVALID` (for the 71/72-byte URL, n = 37: H ≥ 45 pt); `tx = pad + mod·n + gap`, `tw = W − tx −
pad`; lines in this order — name (F2, f, ≤ 2 lines), label (F1, b), date (F1, b) — with the first f in 11…7 that fits
(§3 fit rule, evaluated with the seal label); the operations of §3 step 3 in the same order: the content starts with
`/EIDVerify <</URL (<url>)>> BDC`, then the rotation `q`/`cm` (rot ≠ 0), the frame, the QR block (`q <mod> 0 0 <mod>
<pad> <floor((H − mod·n)/2)> cm` … `Q`), the text lines at `x = tx`, the closing `Q` (rot ≠ 0), and ends with `EMC`. Form
dictionary, widget, 11 objects: §2. Placement: PLACEMENT_SPEC, unchanged.

Equivalently, whenever the citizen label and the seal label fit at the same f (every golden case): `content(QR seal, p)
= content(citizen, p with role "")` with the label line's `<GGGG…>` replaced by the glyphs of the seal label (Go test
`core.TestSealQRContent`, rot 0/90/180/270, mn/en).

Example (golden `seal-qr-visible`, 220 × 64 pt, `TEST ONLY Golden Org LLC`, mn, docId `8c9d0e1f-…`, rev 1): first line
`/EIDVerify <</URL (https://ca.eidmongolia.mn/verify/8c9d0e1f-2a3b-4c4d-8e5f-6a7b8c9d0e1f/1)>> BDC`, `mod = 1.51`,
`q 1.51 0 0 1.51 4 4.06 cm`, `tx = 63.87`, f = 11: `BT /F2 11 Tf 63.87 39.13 Td` (name), `BT /F1 9 Tf 63.87 27.38 Td`
(seal label), `BT /F1 9 Tf 63.87 16.13 Td` (date).

**Writers.** The QR promises that `/verify/<docId>/<rev>` resolves, so a QR seal stamp may only be emitted by a writer
that registers the seal. In this release no public API emits it: Go has only an unexported Prepare option, used by the
golden cases marked `"sealQr": true` in `testdata/golden/manifest.json` (ports enable the variant internally for those
cases). **Writers must not emit the QR seal stamp until the CA and TS validators ship §6.5 / §6.3.** The QR-less stamp
(§6.2) stays valid forever — real documents carry it.

Golden v13 (prepare/complete): `seal-qr-visible` (unsigned 2-page contract, no verify page, mn), `seal-qr-visible-en`,
`seal-qr-rotated90` (`/Rotate 90`), `citizen-then-seal-qr` (docId from the citizen's verify page),
`seal-qr-then-citizen` (the citizen reuses the seal's docId, §6.6 step 2.2), `seal-qr-then-seal-qr`,
`sealv12-then-citizen` (QR-less seal first, then a citizen with a caller-supplied docId, §6.6 step 3).

### 6.6 docId resolution in Prepare (all signers)

Runs after the prechecks (PRECHECKS #1–#10), before the verify page and the stamp are built. "Signed" = PRECHECKS #6
found at least one signature; "verified signatures" = the signature dictionaries (by object number) that PRECHECKS #6
found and #8–#10 accepted.

1. **Unsigned document**: `opts.docId` if given, else a fresh random UUID (16 random bytes, `b[6] = b[6] & 0x0f | 0x40`,
   `b[8] = b[8] & 0x3f | 0x80`, lowercase hex `8-4-4-4-12`) — unchanged. This is the **only** case that generates one.
2. **Signed document** — the first of these that yields a value is the *found* docId:
   1. the **verify-page link**: the first dictionary (xref in object-number order, each in-use object read with the
      generation its xref entry records) with `/Subtype /Link` whose `/A /URI` is `https://ca.eidmongolia.mn/verify/` +
      a lowercase UUID (unchanged, PRECHECKS);
   2. else **`docIdFromStamps`**. Walk the same xref the same way. A *widget* is a dictionary with `/FT /Sig` whose `/V`
      is an **indirect reference** to one of the verified signature dictionaries (a direct `/V` dictionary, or a
      reference to anything else, is ignored). A verified signature with **more than one** widget is ignored entirely
      (one widget per signature, as the validator maps widgets to signatures; a forged widget cannot borrow a genuine
      `/V`). For a signature with exactly one widget: its `/AP` must resolve to a dictionary whose `/N` resolves to a
      stream whose `/Filter` is **absent or `null`** (any other value — a name, or an array, even the empty array `[]` —
      → no candidate); read the first ≤ 128 bytes of the stream's **`/Length` bytes** (as stored, never a scan to
      `endstream`); if they match the §5 step-6 regex at offset 0, the signature is a candidate with the regex's
      `<uuid>`. The docId is the candidate with the smallest `ByteRange[2] + ByteRange[3]` of its signature dictionary
      (the earliest-signed marked stamp — object numbers and xref order do not matter); on a tie, the lower signature
      object number. Stamps without the marker (QR-less seal stamps) and invisible signatures yield no candidate.
      **A read/parse failure anywhere in this walk fails the whole Prepare with `PDF_INVALID`** — a candidate found
      before the failure is never used (fail closed).

   A found docId and a given, different `opts.docId` → `REQUEST_INVALID`; otherwise the found docId is used — for every
   signer, visible or **invisible** (an invisible signature on a document with a marked stamp and no verify page now
   gets the stamp's docId; before, it got `opts.docId` or "").
3. Else (signed, nothing found): `opts.docId` if the caller supplied one — an explicit opt-in: the caller takes
   responsibility for registering that docId;
4. else the docId stays **empty** (`Prepared.docId = ""`). **No random docId is generated on a signed document**: today's
   production CA rejects a rev > 1 registration for an unknown docId (`DOC_NOT_FOUND`), so the QR could never resolve.
   A signature that draws a QR (citizen stamp, §6.5 seal stamp) with an empty docId is `REQUEST_INVALID` (exactly as
   v0.30.0); an invisible signature or a QR-less seal stamp proceeds with the empty docId.

The verify page is still added only to unsigned documents; this rule never adds one. Effect: a citizen can sign a
seal-first document visibly when the seal has a QR (reusing its docId — golden `seal-qr-then-citizen`); after a QR-less
seal only with a caller-supplied docId (`sealv12-then-citizen`), otherwise `REQUEST_INVALID` as before. The CA-side
registry change that allows creating a record at rev > 1 ships later; the default of step 4 may be widened then. No
earlier golden changes: every earlier signed input has a verify page or only an invisible prior signature. PLACEMENT_SPEC
§1a is evaluated with the resolved docId exactly as before; steps 2.2–4 apply only when step 2.1 found no verify-page
link. Go: `resolveDocID` (`pades/prepare.go`), `docIDFromStamps` (`pades/verify.go`, verified set from `precheck`);
tests `TestResolveDocID`, `TestDocIDFromStampsEarliest` (synthetic: earlier stamp has the higher object numbers; direct
`/V`, borrowed `/V`, unverified `/V`, `/Filter []` vs `null`), `TestPrepareDocIDRule`, `TestAppearanceRejects`.
