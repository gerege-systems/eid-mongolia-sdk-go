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
  `{"error": "<код>"}` (`PDF_NO_SIGNATURE`, `PDF_INVALID`, `PDF_TOO_MANY_SIGNATURES`, `PDF_TOO_LARGE`).
- Тохиолдлууд: зөв (B-LT, objstm, linearized, desktop), олон revision, харагдах гарын үсэг (APPEARANCE_SPEC),
  өөрчлөгдсөн байт (`tampered`), гарын үсгийн дараах өөрчлөлт (`modified-after-signing`), итгэмжлэгдээгүй root,
  утасны (qcStatements → QUALIFIED, `key_medium` phone) ба токены (qcStatements-гүй → ADVANCED) гэрчилгээ, онлайн
  OCSP good / revoked / revoked_after_signing, CRL revoked, хариугүй → DSS, CA-ийн хуучин stamp, гарын үсэггүй, PDF биш.
- CA-д `session_id`, `doc_id`, `on_behalf_of_*`, `stamp_lookup` (бүртгэлээс), `key_medium` (бүртгэлээс) нэмэгдэж болно;
  харьцуулахдаа эдгээрийг хасна. `certificate_level` нь SDK-д (CA-д нэмэх санал).

Шинэчлэх: `go test ./pades -run ValidateGolden -update` (оролт, http/, expect бүхэлдээ дахин бичигдэнэ).
