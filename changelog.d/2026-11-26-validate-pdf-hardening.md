### Security — ValidatePDF hardening (validate corpus v14)

Two independent reviews of the .NET and Java ports of `ValidatePDF` found weaknesses that were already in this
reference implementation (and in the TypeScript SDK). Fixed here together with the TS SDK; 13 new conformance cases in
`pades/testdata/validate` (`manifest.version` 14, README «v14») let the ports prove the same behaviour. All 67 earlier
cases keep their exact reports.

- **Shadow attack** (`pades/internal/validate/revisions.go` `diff`): an object of the signed revision whose stream
  `/Length` ran past the signed bytes, completed by a later (e.g. DSS-only) revision, was never re-parsed because its
  xref entry was unchanged — the signature stayed `valid`. Every unchanged in-use object (and its object stream) must now
  parse completely inside the signed revision, else `modified_after_signing`.
- **Later-signature trust** (`extract.go`, `appearance.go`): only later signatures that pass integrity count as
  signature-only extensions, and an own-signer visible stamp's `/Name` must equal the display name of that signature's
  certificate. A forged later revision with a visible stamp no longer keeps earlier signatures `valid`.
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
- Behaviour visible to integrators: documents with more than 128 incremental updates, object streams with very many
  members, or an own-signer stamp whose `/Name` differs from the certificate name (a custom `PrepareOptions.SignerName`)
  now get `PDF_INVALID` resp. `modified_after_signing` for the earlier signatures.
- Checked: `go vet ./...`, `go test ./...` (new `TestValidatePDFReaderDoS` with time bounds, `TestBoundedCert`,
  `TestExtractDSSDedupe`, `TestValidateGolden` v14; the new corpus inputs run against the previous code: shadow,
  later-signature, doc-signer, weak-algorithm cases were `valid`/`platform_attested`, `objstm-many-members` did not
  finish in 20 s).
