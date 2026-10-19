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
- CA-д `session_id`, `doc_id`, `on_behalf_of_*`, `stamp_lookup` (бүртгэлээс), `key_medium` (бүртгэлээс) нэмэгдэж болно;
  харьцуулахдаа эдгээрийг хасна. `certificate_level` нь SDK-д (CA-д нэмэх санал).

Шинэчлэх: `go test ./pades -run ValidateGolden -update` (expect бүхэлдээ дахин бичигдэнэ; байгаа оролт ба `http/` хэвээр —
шинээр үүсгэхийн тулд файлыг устгана).
