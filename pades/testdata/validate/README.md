# ValidatePDF conformance (pades-validate/1, corpus v15)

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
- **v14** (`manifest.version` = 14; hardening after the .NET/Java port reviews; all 67 earlier cases unchanged, every new
  case offline, inputs written once by `-update` — Go `hardeningVInputs`). Each row: what the input is, and **what a port
  must do** to produce the expected report.

  | case | input | what a port must do |
  |---|---|---|
  | `shadow-stream-dss` | `golden/input/quartz-pdf13.pdf` + R0 (page 1 `/Contents [3 0 R 19 0 R]`, object 19 a content stream whose `/Length` runs past the signed revision) + citizen B-B + DSS-only revision whose `/Certs` stream data holds `endstream endobj` exactly where 19's `/Length` ends | in the revision classifier, every in-use object whose xref entry is unchanged from the signed base must parse completely inside the base bytes (its object stream too); otherwise `modified_after_signing` (was `valid`) |
  | `shadow-control` | same pipeline, object 19 complete inside R0 | stays `valid`, `extended_by_signatures_only` |
  | `later-sig-integrity-failed` | `golden/output/quartz-pdf13.pdf` + citizen B-B second signature with a correct visible stamp but a corrupted RSA signature | only signatures that pass integrity count as later signatures (`known`); the step becomes DSS-only and is rejected → first signature `modified_after_signing` (was `valid` + `visible_later_signature`) |
  | `later-stamp-name-mismatch` | same base + B-B signature by `validate/pki/citizen-qc.pem` (QUALIFIED TESTOV) whose `/Name` and stamp say `GOLDEN TESTOV` | **changed in v15:** the stamp's `/Name` is NOT compared with the certificate's display name → both signatures `valid`; first `extended_by_signatures_only`, `visible_later_signature`; second `signer_name` `QUALIFIED TESTOV`, `claimed_name` `GOLDEN TESTOV` (v14 expected `modified_after_signing`) |
  | `later-stamp-name-control` | same, `/Name` = `QUALIFIED TESTOV` | both signatures `valid`; first `extended_by_signatures_only`, `visible_later_signature` |
  | `doc-signer-attested` | `golden/input/quartz-pdf13.pdf` + B-B by `validate/pki/doc-signer.pem` (EKU documentSigning, issued by 04), `/Name` `GOLDEN TESTOV` | `signer_name_source` `platform_attested` (unchanged rule) |
  | `doc-signer-modified` | `doc-signer-attested` + an `/Info` revision | `platform_attested` only when `covers_whole_document` or `extended_by_signatures_only` → `certificate` with `modified_after_signing` |
  | `weak-sig-alg-sha1-rsa` | `golden/output/quartz-pdf13.pdf` with the SignerInfo `signatureAlgorithm` OID patched to `sha1WithRSAEncryption` (outside ByteRange; integrity still holds) | a SHA-1/MD5 SignerInfo signature algorithm (1.2.840.113549.1.1.2/.4/.5, 1.2.840.10040.4.3, 1.2.840.10045.4.1, 1.3.14.3.2.29) is `weak_algorithm` exactly like a weak digest → `invalid` |
  | `xref-stream-w-zero` | xref stream `/W [0 0 0] /Index [0 1000000000]` | structure pre-check: row width 0 (and the 2^21 entry cap) → `PDF_INVALID` quickly; a reader must never loop per row with a zero width |
  | `xref-stream-zero-rows` | `/W [1 0 0] /Index [0 67108864]`, 64 MiB of zeros (FlateDecode) | entries > 2^21 and the 32 MiB structural inflate budget → `PDF_INVALID` |
  | `xref-prev-chain-129` | 129 classic xref sections chained by `/Prev`, no signature | > 128 xref sections (trailer dicts + `/Type /XRef` dicts counted by the pre-check) → `PDF_INVALID` (was `PDF_NO_SIGNATURE`) |
  | `objstm-many-members` | one FlateDecode ObjStm with 200 000 members, all in the xref stream | Σ (header pairs read × decompressed length) > 1 GiB → `PDF_INVALID`; a reader must index an object stream's header once (Go's external reader re-inflates per member — the pre-check guards it) |
  | `cms-33-certs` | `golden/input/quartz-pdf13.pdf` + citizen B-B whose CMS carries 33 certificates | > 32 certificates in a CMS → `malformed_signature` (also: RSA modulus > 8192 bits, exponent > 2^32−1, serial > 160 bits) |

  Pre-check rules (Go `CheckStructure`, TS `checkStructure` — ports replicate them so reports stay identical): sections =
  dictionaries after the `trailer` keyword + top-level dictionaries with `/Type /XRef` (> 128 → reject); for an xref stream
  dictionary with ≥ 3 integer `/W` entries: each 0…8 and the sum > 0; integer `/Index` pairs: start ≥ 0, count ≥ 0,
  start + count ≤ 2^21; total rows (Index counts, or `/Size` without `/Index`) ≤ 2^21; xref stream with > 1 filter →
  reject, a FlateDecode xref stream's inflated size is charged to the 32 MiB budget shared with object streams; object
  stream work = pairs read in its header (first token not EOF) × decompressed length (uncompressed: min(rest of file,
  direct `/Length`)), summed ≤ 1 GiB.
- **v15** (`manifest.version` = 15; no new case, no input changed; only the expected report of `later-stamp-name-mismatch`
  changed, all other 79 reports byte-identical to v14). **What a port must do:** the own-signer visible stamp's `/Name` is
  NOT compared with the signing certificate's display name — a later signature that passes integrity and whose widget and
  appearance match the PAdES writer for its own `/Name` is a signature-only extension whatever that name is (the
  `/Name` length limit and every other stamp check stay). Why: the released eID Windows desktop client writes the
  signer's Cyrillic portal name into `/Name` while the certificate name is Latin, integrators may pass a custom
  `signerName`, so legitimate countersigned documents were reported `modified_after_signing`; and an untrusted signer
  controls its own certificate name anyway, so the comparison added little. `signer_name` still comes from the
  certificate; `claimed_name` carries `/Name`. The other half of v14 rule B stays: only later signatures that pass
  integrity count (`later-sig-integrity-failed` unchanged).
- CA-д `session_id`, `doc_id`, `on_behalf_of_*`, `stamp_lookup` (бүртгэлээс), `key_medium` (бүртгэлээс) нэмэгдэж болно;
  харьцуулахдаа эдгээрийг хасна. `certificate_level` нь SDK-д (CA-д нэмэх санал).

Шинэчлэх: `go test ./pades -run ValidateGolden -update` (expect бүхэлдээ дахин бичигдэнэ; байгаа оролт ба `http/` хэвээр —
шинээр үүсгэхийн тулд файлыг устгана).
