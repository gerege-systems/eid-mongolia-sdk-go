### Added — validators learn the e-Seal stamp with QR (APPEARANCE_SPEC §6.5, golden v13)

- **Writers must not emit the QR seal stamp until the CA and TS validators ship §6.5.** This release only teaches
  validators the new variant; `pades.SealPDF` still emits the QR-less seal stamp of v0.30.0 (byte-identical, checked
  against the v12 golden DTBS), and there is no public option for the QR (it arrives with seal registration).
- APPEARANCE_SPEC §6.5: the QR seal stamp is the citizen stamp (§3) with the seal label, no role line (even with a CMS
  claimedRole) and `trim(/Name)`; it starts with the `/EIDVerify` marker like the citizen stamp (≥ 45 pt high).
- §6.3 (validator): for an e-Seal certificate the `/EIDVerify` marker at the start of the form stream's `/Length` bytes
  selects the QR variant (step-6 checks: rev = position, docId = verify-page docId when present); no marker → the
  QR-less v12 stamp; no fallback between them. Every cross-combination fails closed. Stamps of different signers
  carrying different docIds are not tampering.
- §6.6 (Prepare docId) on a signed document: verify-page link → else the earliest-signed `/EIDVerify` stamp of a
  verified **e-Seal** signature (citizen stamps are never a source; indirect `/V`, one widget per signature, marker rev =
  the signature's position, `/Filter` absent or direct null; a failure reading that stamp → `PDF_INVALID`) → else the
  caller's `docId` (explicit opt-in) → else empty. A found docId and a different caller `docId` → `REQUEST_INVALID`.
  **No random docId on a signed document** (the CA rejects rev > 1 registrations for unknown docIds): a visible
  signature with no docId stays `REQUEST_INVALID`, as in v0.30.0. Unsigned documents are unchanged.
- **Behaviour change for invisible signatures:** on a signed document with a marked (QR) e-Seal stamp and no verify page,
  `Prepared.DocID` is now the stamp's docId (before: the caller's `docId` or ""), and a different caller `docId` is
  `REQUEST_INVALID`. Visible citizen signatures after a QR seal reuse its docId (before: `REQUEST_INVALID`). Documents signed only by
  citizens resolve exactly as in v0.30.0.
- Golden v13: 7 prepare/complete cases (`seal-qr-*`, `citizen-then-seal-qr`, `seal-qr-then-citizen`,
  `seal-qr-then-seal-qr`, `sealv12-then-citizen`; manifest flag `sealQr`) and 20 validate cases (9 positive incl. two
  controls, 11 negative); all earlier goldens byte-identical. Generated on the CI runner.
