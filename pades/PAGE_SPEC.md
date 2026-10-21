# Баталгаажуулалтын (verify) хуудас — PAGE_SPEC (pades-client/1)

Хэрэгжүүлэлт (reference): `pades/internal/core/vpage.go` (`InsertVerifyPage`, `pageContent`), QR `pades/internal/qr/qr.go`,
фонт `pades/assets`. Native SDK бүр **байт-ижил** гаргана — golden `testdata/golden/output/*.pdf` (хуудастай тохиолдол:
`quartz-pdf13` (mn), `quartz-pdf13-en` (en), `quartz-objstm`, `quartz-linearized`) нь шалгуур. CA-ийн хуучин fpdf хуудастай төрх ойролцоо, байт-ижил биш.

## 1. Хэзээ

Prepare-д `verifyPage = true` **ба** оролтод гарын үсгийн объект алга (PRECHECKS.md #6) үед л — R_sig-ээс ӨМНӨ тусдаа
incremental revision. `pageSha256 = SHA-256(хуудас нэмсэн баримт)`.

## 2. Ерөнхий дүрэм

- Нэгж pt, эх (0,0) зүүн доод. Бүх координат/хэмжээ **бүхэл тоо** (баннерын муруйгаас бусад — тогтмол мөр).
- Content stream ШАХАЛТГҮЙ: үйлдэл бүр ASCII мөр + `\n` (LF). Тоог аравтын бутархайгүй бүхлээр (`%d`).
- Өнгө тогтмол мөр (`<r g b> rg` / `RG`):
  `text = 0.118 0.118 0.118`, `muted = 0.431 0.431 0.431`, `ok = 0.086 0.541 0.31`, `banner = 0.863 0.961 0.902`,
  `line = 0.863 0.863 0.863`, `link = 0.118 0.431 0.863`, QR `0 0 0`.
- Фонт: `/F1` = NotoSans (Regular), `/F2` = NotoSans-Bold — Type0/Identity-H; `/F3` = Courier (стандарт 14, WinAnsi).
- Текст үйлдэл бүр: `<color> rg` мөр, дараа нь `BT /F<id> <size> Tf <x> <y> Td <str> Tj ET`.
  - F1/F2: `<str>` = `<` + glyph ID бүр 4 оронтой ТОМ hex (`%04X`) + `>`; glyph ID = `fonts/*.metrics.json`-ийн `cmap`
    (Unicode code point → GID). cmap-д байхгүй тэмдэгт → `?`-ийн GID.
  - F3: `(` + ASCII, `\` `(` `)`-г `\\` `\(` `\)` болгосон + `)`.
- Текстийн өргөн (1/1000 pt): F1/F2 — `Σ widths[gid] × size` (`widths` = metrics.json, бүхэл); F3 — `600 × тэмдэгт × size`.
  Kerning үгүй.
- Хэвтээ зураас: `line RG` мөр, `0.75 w 42 <y> m 552 <y> l S`.

## 3. Content stream (дарааллаар)

`y` — курсор. «Текст(f, size, x, y, color, s)» = §2-ын текст үйлдэл.

1. Баннер: `0.863 0.961 0.902 rg`, дараа нь яг энэ 11 мөр:
   ```
   48 800 m
   546 800 l
   549.31 800 552 797.31 552 794 c
   552 754 l
   552 750.69 549.31 748 546 748 c
   48 748 l
   44.69 748 42 750.69 42 754 c
   42 794 l
   42 797.31 44.69 800 48 800 c
   h
   f
   ```
2. Текст(F2, 13, 56, 778, ok, Brand + `title`) — Brand = `eID Mongolia` (§3a).
3. Текст(F1, 9, 56, 760, ok, `subtitle`)
4. `y = 724`: зураас(y); Текст(F2, 11, 42, y−17, text, `document`); `y −= 34`.
5. Текст(F1, 8, 42, y, muted, `fileName`); `y −= 14`; файлын нэрийн мөр бүр (§4, ≤ 3): эхнийхээс бусдын өмнө `y −= 14`,
   Текст(F2, 10, 42, y, text, мөр). Дараа нь `y −= 20`.
6. Текст(F1, 8, 42, y, muted, `hashAlg`); Текст(F1, 8, 297, y, muted, `size`);
   Текст(F2, 10, 42, y−14, text, `SHA256`); Текст(F2, 10, 297, y−14, text, HumanSize(fileSize) §5); `y −= 34`.
7. Текст(F1, 8, 42, y, muted, `docHash`); Текст(F3, 9, 42, y−13, text, inSha256 (жижиг hex)); `y −= 31`.
8. Текст(F1, 8, 42, y, muted, `docId`); Текст(F3, 9, 42, y−13, text, docId); `y −= 35`.
9. зураас(y); Текст(F2, 11, 42, y−17, text, `verification`); `y −= 35`.
10. Текст(F1, 9, 42, y, link, verifyUrl); link annotation #1 (§6) = (F1, 9, 42, y, verifyUrl); `y −= 14`.
11. QR (§7): `0 0 0 rg`, тэгш өнцөгтүүд, дараа нь `f` мөр. QR-ийн дээд зүүн булан = (42, y).
12. Текст(F2, 11, 136, y−14, text, `scan`);
    Текст(F1, 9, 136, y−29, muted, `scanHint`);
    Текст(F2, 9, 136, y−43, link, urlHost(verifyUrl)) — urlHost: `https://`/`http://`-ийг хасаад хоёр дахь `/` хүртэл
    (`ca.eidmongolia.mn/verify`).
13. trustUrl хоосон биш бол: Текст(F1, 9, 136, y−60, muted, `trust`);
    Текст(F2, 9, 136, y−74, link, trustUrl); link annotation #2 = (F2, 9, 136, y−74, trustUrl).
14. Footer: зураас(71); Текст(F1, 8, 42, 58, muted, `"CA: " + caName + "  |  TSA: " + tsaName + "  |  " + provider + ": " + providerName`)
    (`|`-ийн хоёр талд ХОЁР зай).

### 3a. Бичвэр (хэл: `lang` = `mn` анхдагч, хоосон бол mn; `en`; бусад → `REQUEST_INVALID`)

| түлхүүр | mn | en |
|---|---|---|
| title (Brand-ийн ард шууд залгана) | `-аар гарын үсэг зурсан баримт` | ` — Electronically signed document` (U+2014) |
| subtitle | `Гарын үсгүүд энэ PDF-д шингэсэн. Доорх холбоосоор эсвэл Adobe Acrobat-ын Signatures самбараар шалгана уу.` | `Signatures are embedded in this PDF. Verify them with the link below or in Adobe Acrobat's Signatures panel.` |
| document | `БАРИМТ` | `DOCUMENT` |
| fileName | `БАРИМТЫН НЭР` | `FILE NAME` |
| hashAlg | `HASH АЛГОРИТМ` | `HASH ALGORITHM` |
| size | `ХЭМЖЭЭ` | `SIZE` |
| docHash | `БАРИМТЫН HASH` | `DOCUMENT HASH` |
| docId | `БАРИМТЫН ID` | `DOCUMENT ID` |
| verification | `ШАЛГАХ` | `VERIFICATION` |
| scan | `Гарын үсгийг шалгах` | `Scan to verify` |
| scanHint | `QR кодыг утасны камераар уншуулах эсвэл холбоосыг нээнэ үү.` | `Scan this QR code with your phone camera to verify.` |
| trust | `Adobe Acrobat-д Монгол Улсын үндэсний Root CA-д итгэх заавар:` | `Adobe Acrobat: trust the Mongolian National Root CA` |
| provider | `Үйлчилгээ` | `Provider` |

Бичвэр UTF-8 (NFC) — яг энэ code point-ууд; бүх glyph фонтын subset-д бий, мөрөндөө багтана (Go тест `TestPageTextsFit`).
`SHA256`, KB/MB/GB, URL, CA/TSA нэр хоёр хэлэнд ижил. mn бичвэрийн эх: CA-ийн хуудасны анхны хувилбар (ca-eidmongolia-mn
18904d75 `pdfsign/page.go`: гарчиг, «Баримтын нэр/ID», «Гарын үсгийг шалгах», QR-ийн тайлбар, Root CA заавар); одоогийн CA
хуудас зөвхөн англи тул бусад нь орчуулга.

Профайлын утгууд: verifyUrl = `https://ca.eidmongolia.mn/verify/` + docId, trustUrl = `https://eidmongolia.mn/trust`,
caName = signerCert-ийн **issuer CN**, tsaName = `eID Mongolia TSA (tsa.timeserver.mn)`, provider = `ca.eidmongolia.mn`,
fileName = PRECHECKS-ийн цэвэрлэгээ (Cc/Cf/Zl/Zp хасах → NFC → trim, 1–120 code point).

## 4. Мөр таслах (файлын нэр: F2, 10 pt, өргөн 510)

`fits(t) = width1000(t) ≤ 510 × 1000`.
1. Нэрийг U+0020-оор хуваана; хоосон хэсгийг алгасна (дараалсан зай нэг болно).
2. `cur = ""`. Үг бүрд: `cand = cur == "" ? word : cur + " " + word`; `fits(cand)` бол `cur = cand`. Үгүй бол `cur`
   хоосон биш бол мөр болгоно, `cur = ""`; дараа нь `word` дангаараа багтахгүй л бол: `word`-ийн эхнээс багтах хамгийн
   урт (≥ 1 code point) хэсгийг мөр болгож, үлдсэнээр давтана; `cur = word` (үлдэгдэл).
3. Төгсгөлд `cur` хоосон биш бол мөр.
4. Мөр > 3 бол эхний 2 мөр + 3 дахь мөрөөс төгсгөлөөс code point хасаж `fits(мөр + "…")` (U+2026) болтол, `мөр + "…"`.

## 5. HumanSize

`b < 1024` → `"<b> B"`; `b < 2^20` → unit 1024, `" KB"`; `b < 2^30` → 2^20, `" MB"`; бусад → 2^30, `" GB"`.
`t = (b × 10 + unit / 2) / unit` (бүхэл хуваалт) → `"<t/10>.<t%10>"`. Жишээ: 14452 → `14.1 KB`.

## 6. Link annotation

Текстийн өргөн `wd = ceil(width1000 / 1000)`; `/Rect [x, y−3, x+wd, y+size]`:
`<< /Type /Annot /Subtype /Link /Rect [x1 y1 x2 y2] /Border [0 0 0] /A << /S /URI /URI (<url>) >> >>` — URL нь
0x21–0x7E ASCII, `(` `)` `\` агуулахгүй (эс бөгөөс алдаа).

## 7. QR

- ISO/IEC 18004, **byte mode**, **ECC M**, хувилбар = 1–6-аас өгөгдөл (`4 + 8 + 8×len` бит) багтах хамгийн бага
  (`verifyUrl` 69 байт → хувилбар 5, 37×37). > 106 байт → алдаа.
- Өгөгдөл: mode `0100`, урт 8 бит, байтууд, terminator `min(4, үлдсэн)` тэг бит, 8-д тэгээр дүүргэх, pad `0xEC 0x11`
  ээлжилнэ. Блок (M): v1 1×16+10, v2 1×28+16, v3 1×44+26, v4 2×32+18, v5 2×43+24, v6 4×27+16 (блок×өгөгдөл+EC).
  Reed–Solomon GF(256) (0x11D), generator ∏(x − α^i), i = 0..ec−1. Interleave: өгөгдөл (байт индекс, дараа нь блок),
  дараа нь EC мөн адил.
- Байршуулалт: finder (0,0), (0,n−7), (n−7,0) + separator; timing мөр/багана 6; alignment төвүүд
  {6, a} × {6, a} (a: v2 18, v3 22, v4 26, v5 30, v6 34; finder-тэй давхцах 3-ыг алгасна); dark module (n−8, 8).
  Формат: `data = (00 << 3) | mask`, BCH(15,5) generator 0x537, XOR 0x5412; бит i (0 = LSB) байрлал:
  i 0–5 → (мөр i, багана 8); 6 → (7,8); 7 → (8,8); 8 → (8,7); 9–14 → (8, 14−i); хоёр дахь хуулбар i 0–7 → (8, n−1−i),
  i 8–14 → (n−15+i, 8). Өгөгдлийн зигзаг: баруун баганаас 2 баганаар, багана 6-г алгасна, дээш/доош ээлжилнэ.
- **Маск ТОГТМОЛ 0**: `(row + col) mod 2 == 0` бол урвуулна (penalty сонголт ХИЙХГҮЙ — бүх хэлэнд ижил матриц).
- Зураг: модуль = 2 pt, quiet zone үгүй (хуудасны цагаан хэсэг). Мөр r (0 = дээд) бүрд хар модулийн тасралтгүй хэвтээ
  хэсэг [s, c) бүрд нэг мөр: `<42 + 2s> <y − 2(r+1)> <2(c−s)> 2 re` (мөр дээрээс доош, багана зүүнээс баруун);
  эцэст нь `f`.

## 8. Объектууд (incremental revision, PROFILE.md §1-ийн бичигч)

Шинэ дугаар `nextID`-ээс дараалан: хуудас, content, F1 (Type0, CIDFontType2, FontDescriptor, FontFile2, ToUnicode),
F2 (мөн 5), F3, link #1, link #2. Объектуудыг энэ дарааллаар бичээд /Pages үндсийг (ижил дугаар, бусад түлхүүр хэвээр,
`/Kids [... <хуудас> 0 R] /Count n+1`) дахин бичнэ. Catalog өөрчлөгдөхгүй (trailer `/Root` = хуучин Catalog).

### 8a. Байрлал (`verifyPagePosition`, golden v9-өөс)

`verifyPagePosition` = `"last"` (анхдагч; хоосон/байхгүй ч мөн) | `"first"`; бусад утга → `REQUEST_INVALID` (хуудас
нэмэгдэх эсэхээс үл хамааран шалгана). Зөвхөн хуудас нэмэгдэх үед (§1) нөлөөтэй; гарын үсэгтэй баримтад үл тоомсорлоно.

- `last`: үндсэн /Pages-ийн `/Kids [k1 … kn <хуудас> 0 R]` — өмнөхтэй байт-ижил.
- `first`: `/Kids [<хуудас> 0 R k1 … kn]` (элемент хоорондын ганц зай, `[` ба `]`-ийн дотор зайгүй) — хуудас баримтын
  1-р хуудас болно. Үүнээс бусад бүх байт (объектын дугаар, дараалал, бусад түлхүүр, `/Count n+1`) `last`-тай ижил.
  Үл харагдах гарын үсгийн widget урьдын адил гаралтын 1-р хуудсанд (энэ үед verify хуудас) орно.

Хуудас үргэлж **үндсэн** /Pages-ийн `/Kids`-д орно (дунд зангилаа руу биш), тиймээс модны дарааллаар эхний эсвэл сүүлийн
хуудас болно. Харагдах гарын үсгийн `appearance.page` ба `suggestPlacement`-ийн хуудасны дугаар **оролтын** баримтын
хуудсаар (нэмэгдсэн хуудсыг тоолохгүй) — PLACEMENT_SPEC §1b.

```
<page>    << /Type /Page /Parent P G R /MediaBox [0 0 595.28 841.89] /CropBox [0 0 595.28 841.89] /Rotate 0 /Resources << /Font << /F1 a 0 R /F2 b 0 R /F3 c 0 R >> >> /Contents d 0 R /Annots [e 0 R f 0 R] >>
<content> << /Length n >>\nstream\n<§3 — үйлдэл бүрийн ард LF>\nendstream
<Type0>   << /Type /Font /Subtype /Type0 /BaseFont /<ps> /Encoding /Identity-H /DescendantFonts [<cid> 0 R] /ToUnicode <tu> 0 R >>
<CID>     << /Type /Font /Subtype /CIDFontType2 /BaseFont /<ps> /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor <fd> 0 R /CIDToGIDMap /Identity /W [0 [w0 w1 … wN-1]] >>
<fd>      << /Type /FontDescriptor /FontName /<ps> /Flags 32 /FontBBox [x0 y0 x1 y1] /ItalicAngle 0 /Ascent A /Descent D /CapHeight C /StemV 80 /FontFile2 <ff> 0 R >>
<ff>      << /Length <len(asset)> /Length1 <length1> /Filter /FlateDecode >>\nstream\n<fonts/*.ttf.zlib байт>\nendstream
<tu>      << /Length n >>\nstream\n<ToUnicode CMap>\nendstream
<F3>      << /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>
```

`<ps>` = `NotoSans` / `NotoSans-Bold`; `/W` = metrics.json `widths` (бүх glyph, зайгаар); BBox/Ascent/Descent/CapHeight/
length1 = metrics.json. ToUnicode CMap (мөр бүр LF, сүүлийн мөрийн ард LF үгүй):

```
/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
/CMapType 2 def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
<k> beginbfchar
<GID> <UNICODE>            ← %04X %04X; glyph ID өсөхөөр, нэг GID-д хамгийн бага code point; ≤ 100 мөрөөр бүлэглэнэ
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end
```

## 9. Asset (`pades/assets/fonts`)

`NotoSans-Regular.ttf.zlib` (SHA-256 `f85ae0d0a493e0657734649038cecb926c68eb451a67cb5460deccffb37d62f7`),
`NotoSans-Bold.ttf.zlib` (`c1e07949ad57d6f9bfeddcdd1eb7b23ff1918b05520e5d38333ed5b302943a11`) — FontFile2 stream-ийн
байт, хэвээр нь бичнэ (runtime-д шахахгүй/задлахгүй); `*.metrics.json` (psName, length1,
unitsPerEm, ascent, descent, capHeight, bbox, widths[gid], cmap[[codepoint, gid]]), `OFL.txt` (лиценз — хамт түгээнэ).
