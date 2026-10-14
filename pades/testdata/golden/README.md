# pades golden vectors (pades-client/1)

Wrapper бүр (WASM/TS, Swift xcframework, Kotlin AAR, .NET DLL) энэ хавтсыг хуулж Go core-той **ижил байт** гаргаж
байгааг шалгана. Үнэний эх сурвалж = энэ хавтас (CA репогийн `testdata/pades-client/` нь хуулбар).

> **`pki/*.pem` нь ЗӨВХӨН ТЕСТИЙН гинж, хувийн түлхүүртэй** (root → 02 → 03 → 04 → иргэн/TSA, RSA-2048, `TEST ONLY …`
> нэртэй). Бодит гинжид итгэгдэхгүй; тестээс өөр зориулалтаар бүү ашигла. `desktop/pki/*.key` — мөн адил.

- `manifest.json` — тохиолдол бүр: `input` (эсвэл `case:<нэр>` — өмнөх тохиолдлын гаралт), `prepare` options
  (signerCert = `pki/citizen.pem`, chain = 04/03/02, roots = `pki/root.pem`, signingTime = `signingTime` нэмэгдэнэ),
  `expect` — `digest`, `dtbs`, `preparedSha256`, `byteRange`, `outSha256`, `cmsSha256`, `revIndex`, `docId`,
  `priorCmsSha256` эсвэл `error` (код).
- Иргэний гарын үсэг = `pki/citizen.pem`-ийн түлхүүрээр DTBS дээр RSA PKCS#1 v1.5 (тодорхойлогдсон).
- `complete`: TSA = `http://tsa.pki.test/`, OCSP/CRL = гэрчилгээний AIA/CDP (`*.pki.test`) — сүлжээгүй: HTTP хариуг
  `http/*.der`-ээс `manifest.http["METHOD URL sha256(body)[:8] hex"]`-ээр өгнө. TSA nonce = `SHA-256` гинж
  (seed `golden-nonce:<case>`; `golden_test.go` `seededReader`), цаг = `now`.
- `input/` — CA-ийн Quartz PDF 1.3 (`quartz-pdf13.pdf`), qpdf `--object-streams=generate` ба `--linearize` хувилбар,
  `encrypted.pdf` (AES-256), CA-ийн хуучин stamp (`stamped.pdf` → `PDF_FOREIGN_SIGNATURE`), desktop-ийн objstm.
  `quartz-pdf13-second` — эхний гаралтын DSS revision дээр 2 дахь гарын үсэг (docID хуудаснаас, onBehalfOf).
- `desktop/` — eid-desktop-ийн Swift port-ын гаралт (`pades/internal/core/desktop_golden_test.go` тулгана).

Шинэчлэх (профайл өөрчлөгдөхөд л): `go test ./pades -run Golden -update` — TSA token шинээр гарна (manifest ба
`http/` бүхэлдээ шинэчлэгдэнэ), дараа нь `ProfileVersion`-ийг нэмнэ.
