# PDF/CMS профайл `pades-client/1`

Native SDK (TS, Swift, Kotlin, C#)-ууд Go reference-тэй (`pades/internal/core/*`, `pades/{prepare,complete,ltv,tsa}.go`)
**байт-ижил** гаргах дүрэм. Бүрэн жишээ: `testdata/golden/output/<case>.pdf` ба `manifest.json`. Бусад баримт:
[PRECHECKS.md](PRECHECKS.md) (prepare-ийн шалгуур), [PAGE_SPEC.md](PAGE_SPEC.md) (verify хуудас), [WIRE.md](WIRE.md)
(TSA/OCSP/CRL хүсэлтийн байт). Эх: ca-eidmongolia-mn `server/internal/pdfsign/pades` (digitorus/pdfsign-ийн fork, BSD-2,
`internal/core/LICENSE.digitorus`); CA-аас ялгаа: runtime-д ШАХАЛТ ҮГҮЙ (xref stream), шууд `/Info`-г хуулна, verify хуудас өөр.

## 0. Prepare / Complete-ийн дараалал

```
prepare(pdf, opts):
  PRECHECKS (1–10) → [verify хуудас: PAGE_SPEC, зөвхөн гарын үсэггүй баримтад] → R_sig (§2) → messageDigest (§3)
  → signedAttrs (§4) → DTBS = SHA-256(signedAttrs) → state
complete(state, signature):
  signature-г DTBS дээр signerCert-ээр шалгах (RSA PKCS#1 v1.5 SHA-256 | ECDSA: r‖s 2×ceil(bits/8) эсвэл DER) → SIGNATURE_INVALID
  → TSA (WIRE.md §1) → CMS (§5) → embed (§6) → OCSP/CRL (§8, genTime-ийн дараа) → R_dss (§7)
```

`signingTime` (`/M`) — үргэлж **UTC+08:00** бүсээр (`(D:YYYYMMDDHHmmSS+08'00')`); тэг бол одоо.
`/Name` = opts.signerName эсвэл гэрчилгээний `GIVENNAME + " " + SURNAME` (хоёулаа алга бол CN).

## 1. Incremental бичигч

Гаралт = **оролт байт-хэвээр** + `\n` + объектууд + xref + trailer. Нэг revision:

- Шинэ дугаар: `nextID = max(trailer /Size, xref-ийн хамгийн их объектын дугаар + 1)`; `reserve()` дараалан.
- Объект: `\n` + `<id> <gen> obj\n` + body (эхлэл/төгсгөлийн whitespace-гүй) + `\nendobj\n`. Xref offset = `<id>`-ийн байрлал.
- Stream body: `<< /Length n[ …] >>\nstream\n` + data + `\nendstream`.
- Бичсэний дараа `\n`, дараа нь xref — оролтын **сүүлийн xref-ийн төрлөөр**:
  - **table**: `xref\n`; дугаараар эрэмбэлж дараалсан хэсгүүд (subsection) `"<first> <count>\n"`, мөр бүр
    `%010d %05d n\r\n` (20 байт); `trailer\n<< /Size <nextID> /Root <cat> 0 R[ /Info …][ /ID [<hex> <hex>]] /Prev <prev> >>\nstartxref\n<xref offset>\n%%EOF\n`.
  - **stream**: xref stream объект өөрөө шинэ дугаар (`reserve()`) авч өөрийн мөрийг Index-д оруулна;
    `<x> 0 obj\n<< /Type /XRef /Length <5×N> /W [1 4 1] /Prev <prev> /Size <nextID> /Index [<first count> …] /Root <cat> 0 R[ /Info …][ /ID …] >>\nstream\n`
    + мөр бүр `01 <offset uint32 BE> <gen uint8>` **шахалтгүй, /Filter үгүй** + `\nendstream\nendobj\nstartxref\n<offset>\n%%EOF\n`.
- `/Prev` = оролтын сүүлийн `startxref`-ийн утга. `/Info`: шууд бус бол `N G R`; шууд толь бол §1a-аар хуулна.
  `/ID`: оролтод 2 элементтэй массив бол хоёулаа hex string (байт хэвээр) хуулна.

### 1a. Утга хуулах (`serialize`)

Container объект доторх ШУУД утгыг дахин бичнэ, өөр объект руу заалтыг `N G R`. string → `<жижиг hex>` (байт хэвээр),
name → `/` + 0x21–0x7E-ээс гадуурх ба `#()<>[]{}/%` байтыг `#XX` (ТОМ hex), integer → аравтын, real → экспонентгүй
хамгийн богино (`strconv.FormatFloat(f,'f',-1,64)`), bool, `null` (байхгүй объект руу заалт ч `null`), dict → `<<` +
(түлхүүр бүр: ` /Key ` + утга) + ` >>` (түлхүүрийн дараалал = задлагчийн өгсөн — Go digitorus/pdf: **байтын өсөхөөр**),
array → `[` + зайгаар + `]`. Гүн ≤ 32.

## 2. R_sig (гарын үсгийн revision)

Дугаар: `sigID, fieldID, catID` дараалан reserve.

1. **Sig толь** (`sigID`), яг энэ байтаар (`␠` = зай):
   ```
   <<\n /Type /Sig\n /Filter /Adobe.PPKLite\n /SubFilter /ETSI.CAdES.detached\n /ByteRange <40 зай>\n /Contents <<57344 × '0'>>\n /M (D:…)[\n /Name <hex>][\n /Reason <hex>]\n>>
   ```
   `/Name`, `/Reason`: trim; хоосон, UTF-8 буруу, U+0000–001F / U+007F / Cc, эсвэл `" obj"`, `endobj`, `stream`, `xref`,
   `trailer`, `%%EOF` агуулсан, UTF-16 нэгж > 120 (`/Name`) / 127 (`/Reason`) бол БИЧИХГҮЙ. ASCII бол байтыг hex, эс
   бөгөөс `FEFF` + UTF-16BE hex.
2. **Widget/талбар** (`fieldID`): `<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [0 0 0 0]\n[  /P <page> <gen> R\n]  /F 132\n  /FT /Sig\n  /T (Signature k)\n  /V <sigID> 0 R\n>>`
   — `k` = AcroForm /Fields-ийн `/FT /Sig` тоо + 1, нэр давхцвал k++. `/P` = /Pages модны эхний /Page (гүн ≤ 32).
3. Эхний хуудасны `/Annots`-д widget: `/Annots` шууд бус массив бол тэр массивыг (ижил дугаар/үе) `[… <fieldID> 0 R]`;
   эс бөгөөс хуудсыг (ижил дугаар/үе) бусад түлхүүрээр (§1a) + ` /Annots [… <fieldID> 0 R]` дахин бичнэ.
4. **Catalog** (`catID`): `<<\n  /Type /Catalog\n` + [`  /Version /1.5\n` — Catalog-д /Version алга ба толгой < 1.5 бол]
   + хуучин Catalog-ийн /Type, /AcroForm-оос бусад түлхүүр бүр `  /Key <утга>\n` + `  /AcroForm <<` + (хуучин AcroForm-ийн
   /Fields /SigFlags-аас бусад түлхүүр ` /Key утга`) + ` /Fields [<хуучин заалтууд, зай> <fieldID> 0 R] /SigFlags 3 >>\n>>`.
5. finish (§1). ByteRange: `a` = `/Contents <`-ийн `<`-ийн байрлал, `b = a + 2×28672 + 2`, `c = len − b`;
   `"[0 a b c]"`-г 40 зайны эхэнд бичнэ (үлдсэн нь зай).

## 3. messageDigest

`SHA-256(pdf[0:a] ‖ pdf[b:b+c])`.

## 4. signedAttrs (DER SET OF, tag 0x31)

Attribute = `SEQUENCE { OID, SET { value } }`; элементүүдийг **кодчилсон байтаар өсөхөөр** эрэмбэлнэ (X.690 §11.6):

| OID | value |
|---|---|
| 1.2.840.113549.1.9.3 contentType | OID 1.2.840.113549.1.7.1 (id-data) |
| 1.2.840.113549.1.9.4 messageDigest | OCTET STRING (32) |
| 1.2.840.113549.1.9.16.2.47 signingCertificateV2 | `SEQ { SEQ { SEQ { OCTET SHA-256(cert DER), SEQ { SEQ { [4] EXPLICIT <cert.issuer Name DER> }, INTEGER serial } } } }` (hashAlgorithm орхино) |
| 0.4.0.19122.1.1 signer-attributes-v2 (claimedRole хоосон биш бол) | `SEQ { [0] EXPLICIT SEQ { SEQ { OID 2.5.4.72, SET { UTF8String role } } } }` (role ≤ 900 code point) |

signingTime **үгүй**. Жишээ (golden `quartz-pdf13`, тестийн cert, claimedRole үгүй):

```
3181d1 301806092a864886f70d010903310b06092a864886f70d010701
       302f06092a864886f70d01090431220420 47b4f254b9d7f9ac9cf3738cf7714c3c1ae4132bba544cd4233e1116a54b438e
       308183060b2a864886f70d010910022f3174 3072 3070 306e 0420 b241059e0db04b9531b777947e1ff9cea97d7b0cf1d0520ad0dee406a49a018f
              304a 3044 a442 3040 <issuer Name> 020203ed
DTBS = SHA-256(дээрх) = 2ee21e8694552637666c7db63db958bc255dec3788a74a6432c34d81e211895a
```

## 5. CMS (ContentInfo → SignedData)

```
SEQ { OID 1.2.840.113549.1.7.2, [0] EXPLICIT SEQ {
  INTEGER 1,
  SET { SEQ { OID sha256 } },                      -- digestAlgorithms (параметргүй)
  SEQ { OID id-data },                             -- detached
  [0] IMPLICIT { cert DER … },                     -- signer + chain (04,03,02; root-гүй, signer-тэй давхардсаныг хасна), DER байтаар өсөхөөр
  SET { SEQ {                                      -- SignerInfo
    INTEGER 1,
    SEQ { <signer.issuer Name DER>, INTEGER serial },
    SEQ { OID sha256 },
    [0] IMPLICIT signedAttrs                       -- §4-ийн байт, эхний 0x31 → 0xA0
    SEQ { OID sha256WithRSAEncryption, NULL } | SEQ { OID ecdsa-with-SHA256 },
    OCTET STRING signature,                        -- RSA хэвээр; ECDSA DER (r‖s бол DER болгож)
    [1] IMPLICIT { SEQ { OID 1.2.840.113549.1.9.16.2.14, SET { TimeStampToken DER } } }
  } } } }
```

INTEGER нь DER-ийн хамгийн богино (эерэг тоонд дээд бит 1 бол 0x00 угтвар). Урт нь DER-ийн богино/урт хэлбэр.

## 6. Embed

`len(cms) ≤ 28672` (эс бөгөөс `PLACEHOLDER_OVERFLOW`); `/Contents`-ийн `<` дараах `2×len` тэмдэгтийг CMS-ийн **жижиг
hex**-ээр солино, үлдсэн `0` хэвээр. Өөр байт өөрчлөгдөхгүй.

## 7. R_dss

DSS = {Certs, OCSPs, CRLs (DER, §8-ийн дарааллаар), Contents = `/Contents`-ийн hex тайлсан БҮТЭН байт (тэг дүүргэлттэй)}.

1. Хуучин `/DSS`-ийн `/Certs /OCSPs /CRLs` массивын заалтуудыг (§1a) дарааллаар нь хадгална; stream бүрийн
   агуулгын SHA-256 → заалт.
2. Шинэ мөр бүр (Certs, дараа нь OCSPs, CRLs): агуулга нь хуучин/шинэ stream-тэй ижил бол тэр заалт; эс бөгөөс шинэ объект
   `<< /Length n >>\nstream\n<DER>\nendstream` (шахалтгүй), заалтыг жагсаалтын төгсгөлд. VRI-ийн тухайн ангилалд заалт
   (давхардалгүй, дарааллаар).
3. DSS толь (шинэ дугаар): `<<` + (` /Certs [..]`, ` /OCSPs [..]`, ` /CRLs [..]` — хоосон биш бол) + ` /VRI <<` + хуучин
   VRI-ийн бусад түлхүүр (§1a) + ` /<HEX(SHA-1(Contents)) ТОМ> << /Cert [..] /OCSP [..] /CRL [..] >>` (хоосон ангиллыг
   орхино) + ` >> >>`.
4. Catalog (шинэ дугаар): `<<\n  /Type /Catalog\n` + /Type, /DSS-ээс бусад түлхүүр `  /Key утга\n` + `  /DSS <id> 0 R\n>>`.
5. finish. Жишээ (golden `quartz-pdf13`):
   `<< /Certs [37 0 R 38 0 R 39 0 R 40 0 R 41 0 R] /OCSPs [42 0 R 43 0 R 44 0 R] /CRLs [45 0 R 46 0 R 47 0 R 48 0 R] /VRI << /A24F351F73819A6A93BBFC1D043BC99DDFBAB872 << /Cert [...] /OCSP [...] /CRL [...] >> >> >>`

## 8. LTV цуглуулалт (OCSP/CRL)

Гинжүүд: `[signerCert, chain…]`, дараа нь TSA token-ий гэрчилгээнүүд (token-д байгаа дарааллаар). Гинж бүрийн
гэрчилгээ бүрд (давхардсан ба root-ыг алгасна):
1. Certs-д нэмнэ (давхардалгүй).
2. Олгогч = (бүх гинжийн гэрчилгээ + roots)-оос subject = issuer, гарын үсэг шалгагдах эхнийх; алга бол `LTV_UNAVAILABLE`.
3. OCSP: AIA OCSP URL бүрд дарааллаар (WIRE.md §2) — хариу олгогчийн (эсвэл OCSPSigning EKU-тэй delegated) гарын
   үсэгтэй, `good`, `nextUpdate ≥ now`; гинжийн **эхний** гэрчилгээнд (иргэн, TSA) `thisUpdate > genTime`. Эхний
   хүчинтэйг OCSPs-д нэмж (delegated responder cert-ийг Certs-д), бусад URL-ийг алгасна.
4. CRL: CDP URL бүрд дарааллаар GET — олгогчийн гарын үсэгтэй, `issuer` = cert.issuer, `nextUpdate ≥ now`, serial
   цуцлагдаагүй бол CRLs-д нэмнэ (ижил URL-ийг нэг удаа татна).
5. (3) ба (4)-өөс нэг ч хүчинтэй алга → `LTV_UNAVAILABLE`.

Хүлээлт: `t0 = truncate(genTime, 1 с) + 2 с`; `now < t0` бол `min(t0 − now, 5 с)` хүлээнэ; эхний гэрчилгээний OCSP
`thisUpdate ≤ genTime` бол 1 с тутам дахин (нийт хүлээлт ≤ 5 с), эс бөгөөс `LTV_UNAVAILABLE`.
