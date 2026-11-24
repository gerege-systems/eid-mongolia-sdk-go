# ValidatePDF conformance (pades-validate/1)

Нэг багцыг **Go `pades.ValidatePDF`**, **TS `validatePdf`** (`@gerege-systems/eid-mongolia-sdk/validate`) ба CA-ийн
`validate.ValidatePDF` (`/v3/validate/pdf`) ажиллуулж **ижил JSON тайлан** гаргана. Үнэний эх сурвалж = энэ хавтас
(TS SDK `scripts/sync-pades-golden.mjs`-ээр бэхэлсэн commit-оос хуулна).

> **ЗӨВХӨН ТЕСТИЙН PKI** (`../golden/pki`, `pki/citizen-qc.pem`) — бодит гинжид итгэгдэхгүй. `pki/*.key.pem` нь тестийн
> хувийн түлхүүр (зөвхөн Go `-update`-д; native SDK-ууд хуулахгүй). PII байхгүй (TESTOV GOLDEN / TESTOV QUALIFIED).

- `manifest.json` — `time` (шалгах цаг), `roots` / `issuers` (testdata-аас харьцангуй PEM), `cases[]`:
  `input` (testdata-аас харьцангуй PDF), `offline`, `nationalRoots` (true — `roots` хоосон: SDK-д шигтгэсэн бодит
  Mongolian National Root CA, тестийн гинж итгэмжлэгдэхгүй), `http` (онлайн OCSP/CRL-ийн хариу: түлхүүр
  `METHOD URL hex(sha256(body))[:16]` → `http/<файл>`; жагсаалтад байхгүй хүсэлт → HTTP 404), `expect` — тайлан эсвэл
  `{"error": "<код>"}` (`PDF_NO_SIGNATURE`, `PDF_INVALID`, `PDF_ENCRYPTED`, `PDF_TOO_MANY_SIGNATURES`, `PDF_TOO_LARGE`).
- Тохиолдлууд: зөв (B-LT, objstm, linearized, desktop), олон revision, харагдах гарын үсэг (APPEARANCE_SPEC),
  өөрчлөгдсөн байт (`tampered`), гарын үсгийн дараах өөрчлөлт (`modified-after-signing`), итгэмжлэгдээгүй root,
  утасны (qcStatements → QUALIFIED, `key_medium` phone) ба токены (qcStatements-гүй → ADVANCED) гэрчилгээ, онлайн
  OCSP good / revoked / revoked_after_signing, CRL revoked, хариугүй → DSS, CA-ийн хуучин stamp, гарын үсэггүй, PDF биш, шифрлэгдсэн (`input/encrypted-*.pdf` — pyHanko-оор тестийн
  PKI-гаар зурсан RC4-128 / AES-128 / AES-256 хоосон хэрэглэгчийн нууц үгтэй ба RC4-128 нууц үгтэй; бүгд
  `PDF_ENCRYPTED`, `-update` дахин бичихгүй).
- **v4** (`pades-golden-v4`, бүгд `offline`, оролт = `golden/output/quartz-pdf13.pdf`-ийн гарын үсгийн revision + өөр DSS
  revision: иргэний OCSP ба 04-ийн CRL-ийг сольсон/хассан, бусад нотолгоо хэвээр; T = 2026-10-14T04:00:00Z, TSA = T+1с,
  шалгах цаг = T+30с; `issuers`-д тестийн өөр eID олгогч `pki/05.pem` нэмэгдсэн). Дүрэм — Go `validate.FreshAt`,
  `OCSPCertIDMatches`, `CRLFor` (README §7.2 «Цуцлалтын нотолгооны дүрэм»):

  | case | DSS-ийн иргэний нотолгоо | indication · problems · revocation |
  |---|---|---|
  | `dss-ocsp-stale` | good, thisUpdate T−400 хоног, nextUpdate-гүй | indeterminate · revocation_unavailable · unknown |
  | `dss-ocsp-expired` | good, T−2ц…T−1ц | indeterminate · revocation_unavailable · unknown |
  | `dss-ocsp-future` | good, thisUpdate T+2ц | indeterminate · revocation_unavailable · unknown |
  | `dss-ocsp-other-serial` | good, serial 9999 | indeterminate · revocation_unavailable · unknown |
  | `dss-ocsp-other-issuer` | good, иргэний serial, CertID = 03-ийн нэр/түлхүүр (04 зурсан) | indeterminate · revocation_unavailable · unknown |
  | `dss-ocsp-revoked` | revoked T−1ц + цэвэр 04 CRL | invalid · revoked · revoked (T−1ц) |
  | `dss-ocsp-revoked-after-signing` | revoked T+3с | valid · revoked_after_signing · revoked (T+3с) |
  | `dss-crl-revoked` | good OCSP + иргэнийг агуулсан 04 CRL (T−2ц) | invalid · revoked · revoked (T−2ц) |
  | `dss-crl-wrong-issuer` | 05-ийн цэвэр CRL л | indeterminate · revocation_unavailable · unknown |
  | `dss-crl-only` | цэвэр 04 CRL л | valid · — · good |
  | `dss-no-revocation` | алга | indeterminate · revocation_unavailable · unknown |
  | `deep-nesting` | — (Catalog-д 300 түвшний массив) | `{"error":"PDF_INVALID"}` |
  | `deep-nesting-objstm` | — (FlateDecode ObjStm-д 300 түвшин, xref stream) | `{"error":"PDF_INVALID"}` |

  `ltv`, `signature_level` нь `expect`-д (нотолгоо хасагдсан бол иргэн `ltv.missing`-д, түвшин `-T`). v3-ийн бүх
  тохиолдол хэвээр. `-update` нь байгаа оролт/`http/` файлыг дахин бичихгүй болсон (шинээр үүсгэхийн тулд устгана).
- **v12** (APPEARANCE_SPEC.md §6, seal stamp; all earlier cases unchanged): `seal-visible`, `seal-visible-en`,
  `seal-after-two-citizens` (golden/output seal cases — every signature valid, earlier ones `extended_by_signatures_only`,
  `visible_later_signature`); negative `seal-stamp-citizen-cert` (a citizen certificate whose second revision draws the
  seal stamp) and `citizen-stamp-seal-cert` (an e-Seal certificate drawing the citizen stamp) — both on
  `golden/output/quartz-pdf13.pdf`, second signature B-B (no timestamp/DSS); the first signature is
  `modified_after_signing`. Inputs written by `-update` (Go `vMismatchedStamp`, test-only — Prepare never emits them).
- **v13** (APPEARANCE_SPEC.md §6.5 seal stamp with QR, §6.3; all earlier cases unchanged): positive (golden/output) —
  `seal-qr-visible`, `seal-qr-visible-en`, `seal-qr-rotated90`, `citizen-then-seal-qr`, `seal-qr-then-citizen`,
  `seal-qr-then-seal-qr`, `sealv12-then-citizen` (two stamps with different docIds — not tampering). Negative (second
  signature B-B on `golden/output/quartz-pdf13.pdf`, 340, 36, 220 × 64 pt on page 1; the first signature is
  `modified_after_signing`): `seal-qr-citizen-cert` (citizen certificate + QR seal stamp), `seal-qr-with-role` (e-Seal
  certificate with a CMS claimedRole, QR seal stamp drawn with the role line), `seal-qr-wrong-rev` (marker rev 3),
  `seal-qr-docid-vs-page` (marker docId ≠ verify-page docId), `seal-v12-with-marker` (marker + QR-less seal content +
  `EMC`), `seal-qr-height-44pt` (220 × 44 pt, 0.97 pt QR modules), `seal-marker-not-at-start` (marker after the first
  line of a QR-less seal stream), `seal-qr-flate` (QR seal stream FlateDecode-compressed, `/Filter /FlateDecode`),
  `seal-qr-marker-crlf` (`BDC\r\n`), `seal-qr-rev-02` (rev `02`), `seal-qr-uuid-uppercase` (on
  `golden/output/quartz-pdf13-nopage.pdf`, no verify page). Passing controls from the same generator, each negative
  differing in one field: `seal-qr-control` (QR seal stamp, e-Seal certificate, rev 2, page docId) and
  `seal-qr-control-nopage` (same on the no-verify-page base). Inputs written by `-update` (Go `vStampRev` with the
  test-only `core.VisibleTamper` hooks `SealRole`, `NoMinModule`, `Body`).
- CA-д `session_id`, `doc_id`, `on_behalf_of_*`, `stamp_lookup` (бүртгэлээс), `key_medium` (бүртгэлээс) нэмэгдэж болно;
  харьцуулахдаа эдгээрийг хасна. `certificate_level` нь SDK-д (CA-д нэмэх санал).

Шинэчлэх: `go test ./pades -run ValidateGolden -update` (expect бүхэлдээ дахин бичигдэнэ; байгаа оролт ба `http/` хэвээр —
шинээр үүсгэхийн тулд файлыг устгана).
