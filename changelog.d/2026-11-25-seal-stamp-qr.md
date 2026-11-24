### Added — validators learn the e-Seal stamp with QR (APPEARANCE_SPEC §6.5, golden v13)

- **Writers must not emit the QR seal stamp until the CA and TS validators ship §6.5.** This release only teaches
  validators the new variant; `pades.SealPDF` still emits the QR-less seal stamp of v0.30.0 (byte-identical, checked
  against the v12 golden DTBS), and there is no public option for the QR (it arrives with seal registration).
- APPEARANCE_SPEC §6.5: the QR seal stamp is the citizen stamp (§3) with the seal label, no role line (even with a CMS
  claimedRole) and `trim(/Name)`; it starts with the `/EIDVerify` marker like the citizen stamp (≥ 45 pt high).
- §6.3 (validator): for an e-Seal certificate the `/EIDVerify` marker at the start of the form stream selects the QR
  variant (step-6 checks: rev = position, docId = verify-page docId when present); no marker → the QR-less v12 stamp.
  Every cross-combination fails closed. Stamps of different signers carrying different docIds are not tampering.
- §6.6 (Prepare docId): verify-page link → else the earliest-signed `/EIDVerify` stamp's docId → else `opts.docId`
  (must equal a found one, else `REQUEST_INVALID`) → else a random docId when the signature draws a QR, now also on a
  signed document. A citizen can now sign visibly after a seal (reusing the seal QR's docId, or a fresh one after a
  QR-less seal); before, that was `REQUEST_INVALID` ("docId required").
- Golden v13: 7 prepare/complete cases (`seal-qr-*`, `citizen-then-seal-qr`, `seal-qr-then-citizen`,
  `seal-qr-then-seal-qr`, `sealv12-then-citizen`; manifest flag `sealQr`) and 13 validate cases (7 positive, 6
  negative); all earlier goldens byte-identical. Generated on the CI runner.
