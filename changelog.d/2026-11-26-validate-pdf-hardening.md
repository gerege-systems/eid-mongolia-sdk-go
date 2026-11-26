### Security — ValidatePDF hardening (validate corpus v15)

Two independent reviews of the .NET and Java ports of `ValidatePDF` found weaknesses that were already in this
reference implementation (and in the TypeScript SDK). Fixed here together with the TS SDK; 13 new conformance cases in
`pades/testdata/validate` (`manifest.version` 15, README «v14», «v15») let the ports prove the same behaviour. All 67
earlier cases keep their exact reports.

- **Shadow attack** (`pades/internal/validate/revisions.go` `diff`): an object of the signed revision whose stream
  `/Length` ran past the signed bytes, completed by a later (e.g. DSS-only) revision, was never re-parsed because its
  xref entry was unchanged — the signature stayed `valid`. Every unchanged in-use object (and its object stream) must now
  parse completely inside the signed revision, else `modified_after_signing`.
- **Later-signature trust** (`extract.go`): only later signatures that pass integrity count as signature-only
  extensions. A forged later revision with a visible stamp no longer keeps earlier signatures `valid`. The stamp's
  `/Name` is deliberately not compared with the certificate name (corpus v15, `later-stamp-name-mismatch` stays
  `valid`): the released eID desktop client writes the Cyrillic portal name there while the certificate name is Latin,
  `PrepareOptions.SignerName` may set any name, and an untrusted signer chooses its own certificate name anyway;
  `signer_name` always comes from the certificate.
- **`platform_attested`** (`validate.go`): reported only when the document is covered or extended only by signatures —
  never together with `modified_after_signing`.
- **Weak signature algorithm** (`extract.go`): a SHA-1/MD5 SignerInfo signature algorithm (`sha1WithRSAEncryption`,
  `ecdsa-with-SHA1`, …) is `weak_algorithm` even with a SHA-256 digest.
- **DoS** (no signature needed): the structure pre-check (`nesting.go`) now rejects (`PDF_INVALID`) > 128 xref sections,
  xref stream rows of width 0 or `/W` entries outside 0…8, > 2^21 xref stream rows in total, multi-filter xref streams,
  more than 32 MiB of inflated xref + object streams, and object-stream member lookups whose work (header pairs ×
  inflated length) exceeds 1 GiB — the external reader (`github.com/gerege-systems/pdf`) re-inflates an object stream
  for every member (a 1.2 MB file took hours). Per signature: > 32 CMS certificates, an RSA modulus > 8192 bits or
  exponent > 2^32−1, or a certificate/TSTInfo serial > 160 bits → `malformed_signature` (timestamp: `timestamp_invalid`).
  DSS: ≤ 8 MiB decoded in total, duplicate references read once, each OCSP/CRL parsed and verified once per validation.
- Behaviour visible to integrators: documents with more than 128 incremental updates or object streams with very many
  members now get `PDF_INVALID`; a later revision whose signature fails integrity makes the earlier signatures
  `modified_after_signing`.
- Checked: `go vet ./...`, `go test ./...` (new `TestValidatePDFReaderDoS` with time bounds, `TestBoundedCert`,
  `TestExtractDSSDedupe`, `TestValidatePDFLaterStampNameNotCompared` (Latin and Cyrillic `/Name` ≠ certificate name),
  `TestValidateGolden` v15; the new corpus inputs run against the previous code: shadow,
  later-signature, doc-signer, weak-algorithm cases were `valid`/`platform_attested`, `objstm-many-members` did not
  finish in 20 s).
