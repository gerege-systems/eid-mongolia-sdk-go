### Security — cross-SDK hardening (behaviour changes; conformance corpus `rp-conformance/2`)

Independent reviews of the .NET (0.17.0) and Java (0.2.0) ports found gaps that were identical in every SDK. This
release closes them in Go (reference) together with the TypeScript SDK and publishes corpus version 2 so the .NET/Java
ports adopt the same rules mechanically (`testdata/conformance/README.md` §Changes).

- **Validator** (`ValidateAuth`, `ValidateSign`, `ValidateCertificateChoice`, `TokenService.AuthVerify`, My QR):
  - a citizen certificate with a weak RSA key — modulus < 2048 bits, or public exponent even or < 3 — is rejected
    (`*ValidationError` «гэрчилгээний RSA түлхүүр сул…», corpus key `cert.weak_key`); `NewValidator` returns an error
    when a trust anchor or intermediate has such a key;
  - a subject with more than one SERIALNUMBER or more than one CN is rejected (`subject.duplicate_identity`; My QR:
    `QR_CHAIN_INVALID`) — SDKs could otherwise read different citizens from the same certificate;
  - issuer allowlist (`AllowedIssuerSKIs`, default `CitizenIssuingCASKI`): when the issuer is found in the trust pool
    only ITS key identifier counts — the SKI, or the RFC 5280 method-1 identifier when the CA has no SKI extension. A
    leaf under an SKI-less CA could previously name the allowed CA in its own AKI and pass the allowlist. The leaf AKI
    is used only when no issuer is found (`AllowUntrusted`). Same fix in the My QR chain (`qrChain`);
  - an unknown `TrustConfig.RequiredLevel` is a `NewValidator` error (it was treated as QUALIFIED);
  - new `ValidateAuthOptions.VerifyUserChallenge`: compares `UserChallengeVerifier` even when it is empty (TS rule
    for a present-but-empty verifier); `eidlogin` sets it on the Web2App callback.
- **OCSP checker** (`NewOCSPChecker`): the given issuer must have issued the leaf (name, AKI/SKI, signature, CA, RSA
  ≥ 2048) before any cache lookup or network call — else `OCSPError{Kind: no_issuer}`; the response's CertID
  (issuerNameHash/issuerKeyHash, SHA-1/256/384/512) must match the issuer — else `invalid`; a delegated responder
  with a weak RSA key is `signature`.
- **RP-API paths**: an empty, `.` or `..` path parameter (ETSI id, document number, session id, …) is rejected with
  `ErrInvalidPathParameter` before any request, for every service (check in the shared HTTP layer, `routes.go`).
- **eidlogin**:
  - the default login cookie name is `__Host-eid_login` when the cookie is Secure, has no Domain and Path is `/`
    (otherwise `eid_login`; an explicit `CookieName` is kept). **Logins in flight during the upgrade restart once.**
    A request with more than one cookie of that name is treated as unbound (status `EXPIRED`, callback
    `eid_error=expired`);
  - rate-limit keys never contain the citizen's id: `push:<pushKey>` (the audit HMAC) in the built-in limiter and in
    `Config.RateLimit` / `RateRule.Func` hooks — **a custom hook that parsed `push:<idCode>` must be updated**;
  - with `ClientIP` configured, an empty client IP is the shared `start:unknown` bucket instead of no limit; IPv6
    clients are keyed by their /64 prefix;
  - the in-memory limiter, when its table is full, counts new keys in one shared overflow bucket instead of refusing
    them (existing counters are never evicted); new `RateRule.MaxKeys` (default 10 000).
- **Corpus `rp-conformance/2`**: 2 new reason keys, 11 new rp-validate cases, 7 new OCSP cases, 10 new eidlogin
  scenarios, one changed scenario (`rate-limit-keys`), 12 new PKI files; v1 PEMs unchanged. Generator
  `conformance_gen_test.go` (`go test -run TestConformanceCorpus -update-conformance`).
- Where: `validator.go`, `qr.go`, `ocsp.go`, `routes.go`, `client.go`, `eidlogin/eidlogin.go`; tests `hardening_test.go`,
  `eidlogin/hardening_test.go`, `conformance_test.go`, `eidlogin/conformance_test.go`.
