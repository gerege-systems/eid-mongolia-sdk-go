### Added — organisation e-Seal registration (CA V158, PR #78) and the QR seal stamp writer

- **What:** `(*eid.SealService).RegisterSealedPDF(ctx, orgEtsi, eid.SealRegistration)` → `POST /seal/{orgEtsi}/registrations`
  (201 `Created` / 200 replay, `eid.SealRegistered` = `PDFSignatureRegistered`); body `eid.SealRegistration` = CA
  `dto.SealRegisterRequest` (`docID, revIndex, cms, fileName?, inSha256, sigRevSha256, outSha256, priorCmsSha256?,
  priorRevisionSha256?`), `SealRegistration.Validate()` = the CA's `normalizeSealRegister` format rules (offline);
  409 `PRIOR_MISMATCH` retry via `PriorSignatures` (same combinations as `RegisterSignature`). New codes
  `CodeSealNotFound`, `CodeSealDocMismatch`, `CodeDocIDReserved`; `eid.SealRegisterErrorCodes` = discovery
  `seal.registerErrorCodes`. `(*eid.SealService).SealForDocument(ctx, orgEtsi, digest, docID, revIndex)` — `POST
  /seal/{orgEtsi}` with the V158 `{docId, revIndex}` reservation (SHA-256 only); `Seal` sends the old body unchanged.
- **pades:** `SealOptions.QR` (QR seal stamp, APPEARANCE_SPEC §6.5 — needs a `pades.DocumentSealer`, reserves docId/revIndex
  at seal time; QR + `Invisible` or a signed input without a resolvable docId → `REQUEST_INVALID`), `SealOptions.DocID`,
  `SealOptions.FileName`; `Completed.SealRegistration` (set by `SealPDF` when a docId exists) and
  `pades.SealRegistration(*Completed)`. Default `SealPDF` output is unchanged (QR-less, golden v12 byte-identical).
- **Why:** the CA registers seals since 2026-11-25 (CA changelog «SDK writer-ууд (QR тамга + бүртгэл, багц 3)»); the CA
  and TS validators and the `/verify` bundle (TS 0.49.0) already implement §6.5, which was the gate for a QR writer.
- **Golden:** no new bytes — `SealPDF{QR}` reproduces golden v13 `seal-qr-visible(-en)` DTBS (`TestSealPDFQRMatchesGolden`);
  tag stays `pades-golden-v13`.
- **Where:** `sealregister.go`, `seal.go`, `routes.go`, `client.go`, `pades/seal.go`, `pades/complete.go`; tests
  `sealregister_test.go`, `pades/seal_register_test.go`, `contract_test.go` (`TestContractSealRegistration`, `TestContractSealDTO`);
  `pades/APPEARANCE_SPEC.md` §6.4/§6.5, README (mn/en/zh-CN) §7.3.
- **Verified:** `go vet ./...`, `go test ./...` on the macmini; PR CI.
