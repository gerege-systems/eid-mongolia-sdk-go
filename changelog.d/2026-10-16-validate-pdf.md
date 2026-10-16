### Нэмэгдсэн — `pades.ValidatePDF` (v0.7.0)

- **Юу:** `pades.ValidatePDF(ctx, pdf, ValidateOptions)` — RP өөрийн backend дээр гарын үсэгтэй PDF-ийг CA-ийн нийтийн
  шалгагчийн (`/v3/validate/pdf`) кодоор шалгана, ижил JSON тайлан. Онлайн цуцлалт (AIA OCSP → CDP CRL → DSS fallback,
  `Offline` сонголт), `certificate_level` (eid.CertificateLevelOf), `key_medium` (CA !377; SDK-д гэрчилгээнээс: phone|unknown).
  Шинэ код `PDF_NO_SIGNATURE`; `PDF_TOO_MANY_SIGNATURES` (16-аас их). `Verify` нь `ValidatePDF`+Offline (deprecated, хуучин зан).
- **Засвар:** DSS-ийн OCSP-д олгогч өөрөө зурж өөрийн cert-ээ шигтгэсэн хариуг (RFC 6960 §4.2.2.2) хүлээн авна (v0.6.0
  NewOCSPChecker-тэй ижил).
- **Бусад (CA !377):** `CodeAccountDeletePending` (токен олголтын 409 `ACCOUNT_DELETE_PENDING`); contract тест
  `pdfSigning.registerErrorCodes`-ийг заавал тулгана; `PKICertificate.RevokedAt` SUPERSEDED мөрд ч ирнэ (doc).
- **Яагаад:** хэрэглэгчийн шийдвэр 10-16 — PDF-ийг хөтөч (TS `validatePdf`) ба RP backend (Go) дээр серверт илгээлгүй шалгана.
- **Хаана:** `pades/validatepdf.go`, `pades/verify.go`, `pades/trust.go`, `pades/internal/validate` (CertificateLevel,
  KeyMedium талбар, `CorpusHook` — зөвхөн тест), `pades/testdata/validate/` (conformance багц), `token.go`, `person.go`.
- **Шалгасан:** `go test ./...` (ValidateGolden 25 тохиолдол: зөв B-LT, objstm/linearized, олон revision, харагдах,
  tampered, modified-after-signing, untrusted, QUALIFIED/ADVANCED, онлайн good/revoked/revoked-after/CRL/хариугүй, хуучин
  stamp, гарын үсэггүй, PDF биш); TS SDK 0.20.0 ижил багцыг deep-equal давтана; differential corpus (Go тестийн 121 PDF)
  дээр TS extract 163/163, revisions 161/161, тайлан 121/121 ижил.
