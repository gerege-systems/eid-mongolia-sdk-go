# Prepare-ийн «хөнгөн» шалгуур (pades-client/1)

Native SDK-ууд (TS, Swift, Kotlin, C#) нь бүрэн revision validator-гүй; `prepare` нь **яг энэ** шалгуурыг энэ дарааллаар
хэрэглэнэ. Go reference (`pades/precheck.go`, `Prepare`) ч мөн адил — validator зөвхөн `Verify` ба Go-ийн `Complete`-ийн
self-validation-д. Алдааны код нь эхний унасан алхмынх.

| # | Шалгалт | Код |
|---|---|---|
| 1 | `len(pdf) > 10 223 616` (10 MiB − 256 KiB) | `PDF_TOO_LARGE` |
| 2 | эхний 5 байт `%PDF-` биш | `PDF_INVALID` |
| 3 | signerCert DER задрахгүй; нийтийн түлхүүр RSA эсвэл ECDSA биш | `SIGNER_INVALID` |
| 4 | шифрлэлт: trailer (эсвэл xref stream толь)-д `/Encrypt` байна. Задлагч баримтыг нээж чадахгүй үед файлын байтаас `/Encrypt <int> <int> R` (regex `/Encrypt\s+\d+\s+\d+\s+R`) олдвол мөн шифрлэгдсэн | `PDF_ENCRYPTED` |
| 5 | задрахгүй (xref/trailer, `/Root` толь биш) | `PDF_INVALID` |
| 6 | гарын үсгийн объект = сүүлийн revision-ий xref-ээр хүрэх ШУУД БУС объект бүрээс `/ByteRange` **ба** `/Contents` хоёулаа бүхий толь. Тоо = 0 бол шинэ баримт (`revIndex = 1`, verify хуудас нэмэгдэж болно) | — |
| 7 | тоо ≥ 16 | `PDF_TOO_MANY_SIGNATURES` |
| 8 | гарын үсэг бүр (объектын дугаарын өсөхөөр): `/ByteRange` = 4 бүхэл `[0 a b c]`, `a > 0`, `b > a + 1`, `c ≥ 0`, `b + c ≤ len`; `pdf[a] = '<'`, `pdf[b-1] = '>'`; `pdf[a+1 : b-1]` тэгш урттай hex; тайлсан байтын **эхний ASN.1 SEQUENCE элемент** (тэг дүүргэлт хаягдана) нь CMS SignedData, SignerInfo яг 1, signer cert CMS-ийн certificates-д; гарын үсэг криптограф хүчинтэй: `messageDigest` = hash(`pdf[0:a] ‖ pdf[b:b+c]`) (SignerInfo-ийн digestAlgorithm) ба signedAttrs (DER SET) дээрх гарын үсэг signer-ийн түлхүүрээр (RSA PKCS#1 v1.5 / ECDSA) шалгагдана. Гинж, цуцлалт, хугацаа ШАЛГАХГҮЙ | `PDF_PRIOR_SIGNATURE_INVALID` |
| 9 | DocMDP түгжээ: Catalog `/Perms /DocMDP` толь, эсвэл (6)-ийн аль нэг гарын үсгийн толийн `/Reference` массивын мөр (`/TransformMethod` нь `/DocMDP` эсвэл байхгүй) `/TransformParams /P 1` | `PDF_LOCKED` |
| 10 | гарын үсэг бүр: `/SubFilter /ETSI.CAdES.detached` **ба** signer cert-ийн олгогч нь eID-ийн олгогч CA (шигтгэсэн 04 `eID Mongolia Issuing CA`, 05 `eID Mongolia Organization Issuing CA`, мөн одоогийн signerCert-ийн олгогч = `chain[0]`) — `issuer DN байт тэнцүү` ба cert-ийн гарын үсэг тэр CA-ийн түлхүүрээр хүчинтэй | `PDF_FOREIGN_SIGNATURE` |

`revIndex = (6)-ийн тоо + 1`. Гарын үсэгтэй баримтад verify хуудас **нэмэгдэхгүй**; docID-г (`opts.docId` хоосон бол)
баримтын `/Subtype /Link` annotation-ийн `/A /URI` = `https://ca.eidmongolia.mn/verify/<lowercase UUID>`-ээс уншина
(эхнийх нь); `opts.docId` өгсөн ба таарахгүй → `REQUEST_INVALID`.

**Хөнгөн шалгуурт ОРОХГҮЙ** (Go validator, CA-ийн бүртгэл хариуцна): гинжийн итгэл, цуцлалт, timestamp, гарын үсгийн
дараах өөрчлөлтийн ангилал (revisions.go), LTV бүрэн эсэх, CA-ийн бүртгэлтэй эсэх (`POST /pdf/signatures` → 409).

Golden: `testdata/golden/manifest.json`-ийн `stamped-foreign` (#10), `encrypted` (#4), Go тест `TestPrepareRejects`,
`TestDocMDPLocked` (#9: /Perms ба /Reference).
