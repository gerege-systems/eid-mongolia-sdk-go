### Changed (behaviour — validator, fail-closed chain rule shared with the TS SDK)

- `Validator` (ValidateAuth, ValidateSign, ValidateCertificateChoice, TokenService.AuthVerify — every path through
  `verifyChain`) and the «Миний QR» signer chain (`qrChain`, error `*QRError` `QR_CHAIN_INVALID`) now reject, after a successful `crypto/x509` Verify, a certificate
  path that
  1. contains a CA (trust anchor included) carrying a nameConstraints extension (2.5.29.30), critical or not,
     **even when the leaf satisfies the constraints** — previously accepted when satisfied. Error:
     `*ValidationError` «гэрчилгээний гинж хүчингүй: CA-д name constraints байна (SDK үнэлдэггүй — fail-closed)».
  2. contains, in the leaf or any CA, a critical extension outside {subjectKeyIdentifier, keyUsage, subjectAltName,
     basicConstraints, nameConstraints, cRLDistributionPoints, certificatePolicies, authorityKeyIdentifier,
     extKeyUsage, authorityInfoAccess} — previously critical extensions that Go's x509 parser understands
     (policyConstraints 2.5.29.36, policyMappings 2.5.29.33, inhibitAnyPolicy 2.5.29.54, …) were accepted. Error:
     «гэрчилгээний гинж хүчингүй: үл таних critical extension».
  If several valid paths exist, any path without such a CA still succeeds. The real eID chain (01 → 02 → 03 → 04)
  has neither, so production citizen certificates are unaffected. Why: owner decision 2026-11-26 — one rule in every
  SDK (TS `validator.ts` already behaved this way; .NET/Java ports follow the corpus). Where: `qr.go` `qrChain`, `validator.go`
  `verifyChain`, `criticalUnhandled`, `caFailClosed`; tests `chain_test.go` (satisfied name constraints, critical
  inhibitAnyPolicy) and `rp-validate` corpus cases `auth-chain-name-constraints`, `auth-chain-critical-inhibit-any-policy`.

### Added (tests)

- `testdata/conformance/` (`rp-conformance/1`): language-neutral corpus for all RP SDKs — `rp-validate/cases.json`
  (fixed test PKI, auth/sign/certificate-choice cases with raw session JSON, stored ACSP context, digest, options, fixed
  `now`, expected identity/level or error class + stable reason key), `wire/cases.json` (request method/path/headers/body
  and canned response → parsed result for auth/sign/certificate-choice start and session poll), `interactions_golden.json`,
  `acsp_v2.json`, `ocsp/cases.json` (OCSP checker scenarios with HTTP replay), `eidlogin/scenarios.json` (login backend
  protocol: start/status/callback JSON, cookie attributes, decoy indistinguishability, rate-limit keys, audit events),
  `manifest.json` (SHA-256 of every file, pins of the frozen CA `devicelink_golden.json` and `myqr_vectors.json`) and a
  README describing the format for the .NET/Java ports. Generator `conformance_gen_test.go`
  (`go test -run TestConformanceCorpus -update-conformance`), deterministic (committed test keys, fixed clock);
  `TestConformanceCorpus` fails when the committed corpus is stale. The Go SDK runs the whole corpus
  (`conformance_test.go`, `eidlogin/conformance_test.go`). Verified: `go test ./...` and `go vet ./...` on the macmini;
  CI on the PR.
