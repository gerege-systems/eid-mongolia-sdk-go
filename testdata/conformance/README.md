# RP SDK conformance corpus (`rp-conformance/1`)

One set of language-neutral vectors that every eID Mongolia relying-party SDK (Go — reference, TypeScript, .NET,
Java) must pass. The Go SDK generates it (`conformance_gen_test.go`) and runs it (`conformance_test.go`,
`eidlogin/conformance_test.go`); other SDKs vendor this folder byte-for-byte from a pinned Go commit (tag
`rp-conformance-vN`) and run their own harness against it.

> **TEST DATA ONLY.** `pki/` is a generated test PKI (`TEST ONLY Conformance …`) — it chains to nothing real. No real
> citizen data: the subject is `TESTOV TEST`, `PNOMN-999999990001`. `pki/keys/*.key.pem` are the generator's private
> keys; consumers do **not** vendor them.

## Regenerating

```
go test -run TestConformanceCorpus -update-conformance      # rewrites every generated file
go test ./...                                                # TestConformanceCorpus fails if the corpus is stale
```

Generation is deterministic: fixed keys (`pki/keys/`, created once), fixed clock (`manifest.json` `now` =
2026-10-14T04:00:00Z), RSA PKCS#1 v1.5 for certificates and OCSP, RSA-PSS with a salt derived from the digest, ECDSA per
RFC 6979. Re-running yields identical bytes; `TestConformanceCorpus` (no flag) regenerates in memory and fails on any
byte difference or extra file. `README.md` and `eidlogin/scenarios.json` are hand-written; the generator only hashes them.

## Layout

| Path | Content |
|---|---|
| `manifest.json` | `version`, `now`, `files` (relative path → SHA-256 hex of every file except `manifest.json` and `pki/keys/`), pins of the frozen CA files `devicelinkGolden` and `myqrVectors` (`goPath` in the Go repo, `sha256`) |
| `pki/*.pem` | test PKI, one PEM certificate per file (CAs, OCSP responders, `leaf-*.pem` citizen certificates) |
| `rp-validate/cases.json` | response-validator cases (§rp-validate) |
| `wire/cases.json` | RP-API request/response vectors (§wire) |
| `interactions_golden.json` | byte-exact interactions encoding (§interactions) |
| `acsp_v2.json` | ACSP_V2 payload and digest vectors (§acsp) |
| `ocsp/cases.json` | OCSP revocation-checker scenarios with HTTP replay (§ocsp) |
| `eidlogin/scenarios.json` | login-button backend protocol scenarios (§eidlogin) |

Consumers must check every `files` hash after vendoring, and pin the SHA-256 of their own copy of
`devicelink_golden.json` / `myqr_vectors.json` to the `manifest.json` values (those files are frozen in the CA repo
and are **not** copied into this folder).

Common conventions: JSON is UTF-8; object key order is not significant unless a field says "byte-exact"; base64 is
standard RFC 4648 with padding unless stated; times are RFC 3339 UTC; certificate files are PEM.

## rp-validate

`rp-validate/cases.json`: `{version: "rp-validate/1", trust: {<profile>: Trust}, cases: [Case]}`.

**Trust** — validator configuration (the SDK's `TrustConfig` / `ResponseValidator` options):

| Field | Meaning |
|---|---|
| `anchors` | PEM paths → trust anchors. `[]` = no anchor (must fail `trust.no_anchor`; never "allow untrusted") |
| `intermediates` | PEM paths → intermediate pool. Pass exactly this list (`[]` is not "use the SDK's built-in 02–04") |
| `allowedIssuerSkis` | hex SKIs of CAs allowed to issue citizen certificates |
| `requiredLevel` | absent = `QUALIFIED` |
| `clockSkewSeconds` | absent = 0 |

Key-usage checking is on (SDK default), issuer allowlist as given, scheme name default (`smart-id`).

**Case**:

| Field | Meaning |
|---|---|
| `name`, `comment` | identifier / free text |
| `kind` | `auth` → `validateAuth(session, acsp, options)`; `sign` → `validateSign(session, digest, hashAlgorithm, options)`; `certificateChoice` → `validateCertificateChoice(session, certChoiceSessionId)` |
| `trust` | key into `trust` |
| `now` | validator clock (fixed; skew from the profile) |
| `session` | the raw RP-API `GET /session/{id}` JSON body — parse it with the SDK's own session parser |
| `acsp` | (auth) the stored ACSP context returned at session start: `rpChallenge`, `relyingPartyName`, `brokeredRpName`, `interactions` (base64 string — use as is, never re-encode), `initialCallbackUrl`, `flowTypes`, `signatureAlgorithm`, `hashAlgorithm` |
| `digest`, `hashAlgorithm` | (sign) the digest sent at session start (base64) and its hash |
| `options` | auth: `expectedFlowType`, `userChallengeVerifier`; sign: `expectedFlowType`, `expectedAlgorithm`, `expectedCertificate` (base64 DER) |
| `certChoiceSessionId` | (certificateChoice) returned on the signer object |
| `expect` | exactly one of `ok` or `error` |

`expect.ok`: `documentNumber`, `certificateLevel` (the effective level), `certificateSha256` (hex SHA-256 of the
returned certificate DER), `subject` {`serialNumber`, `givenName`, `surname`, `country`, `commonName`} (`""` = absent),
`signatureAlgorithm` (sign only; `""`/absent otherwise). For `certificateChoice` the signer also echoes
`certChoiceSessionId` and `certificateDerB64` = base64 of the certificate.

`expect.error`: `{class, reason}` or `{class, endResult}`.

- `class` — `ValidationError` (response not trustworthy) or `SessionFailedError` (session completed with
  `endResult ≠ OK`; `endResult` given, `UNKNOWN` when missing).
- `reason` — a stable key. **Error messages are prose (Mongolian) and are never compared.** Each SDK maps its own
  failure to these keys (Go/TS do it in the test harness by message pattern; a new SDK should attach the key to its
  error). Keys are listed in check order; the first failing check wins, so an SDK must perform the checks in this order:

| Key | Check |
|---|---|
| `session.not_complete` | `state ≠ COMPLETE` (SessionFailedError when COMPLETE and endResult ≠ OK) |
| `protocol.mismatch` | `signatureProtocol` present and ≠ `ACSP_V2` (auth) / `RAW_DIGEST_SIGNATURE` (sign) |
| `response.no_certificate`, `response.no_signature` | `cert.value` / `signature.value` missing (no signature check for certificateChoice) |
| `response.no_document_number` | `result.documentNumber` missing |
| `cert.malformed` | certificate is not base64 DER X.509 |
| `cert.not_yet_valid`, `cert.expired` | leaf validity vs `now ± skew` (`notAfter == now` is valid) |
| `purpose.auth_digital_signature`, `purpose.auth_client_auth` | auth leaf: KeyUsage digitalSignature; EKU clientAuth or anyExtendedKeyUsage |
| `purpose.sign_non_repudiation` | sign / certificateChoice leaf: KeyUsage nonRepudiation (contentCommitment) |
| `trust.no_anchor` | no trust anchor configured |
| `chain.critical_extension` | leaf or any chain CA has a critical extension not in the handled set (below) |
| `chain.name_constraints` | any CA on the path (anchor included) carries a nameConstraints extension, satisfied or not |
| `chain.path_len` | pathLenConstraint exceeded |
| `chain.eku` | leaf or CA EKU present and lacks the purpose (auth → clientAuth, sign → emailProtection) and anyExtendedKeyUsage |
| `chain.not_ca` | issuer not CA:TRUE or KeyUsage without keyCertSign |
| `chain.expired` | a CA is outside its validity at the chain time (`now` clamped into the leaf validity) |
| `chain.untrusted` | no path from the leaf to an anchor |
| `issuer.not_allowed` | direct issuer SKI (or leaf AKI) not in `allowedIssuerSkis` |
| `level.qc_malformed` | qcStatements extension not a SEQUENCE OF SEQUENCE |
| `level.claimed_higher` | `cert.certificateLevel` higher than the level derived from the certificate |
| `level.insufficient` | effective level below `requiredLevel` |
| `auth.server_random` | `serverRandom` missing or < 18 bytes |
| `auth.user_challenge` | `userChallenge` not 43 base64url chars |
| `auth.flow_not_offered` | `flowType` not in `acsp.flowTypes` |
| `flow.mismatch` | `options.expectedFlowType` given and ≠ `flowType` (auth and sign) |
| `auth.verifier_required` | expected flow Web2App/App2App without `userChallengeVerifier` |
| `auth.verifier_mismatch` | base64url(SHA-256(verifier)) ≠ `userChallenge` |
| `auth.interaction_type_missing` | `interactionTypeUsed` missing |
| `sign.certificate_mismatch` | `expectedCertificate` given and not byte-identical |
| `alg.unsupported` | unknown `signatureAlgorithm`, or rsassa-pss without a supported `signatureAlgorithmParameters.hashAlgorithm` |
| `alg.key_mismatch` | algorithm family does not match the key (RSA names need RSA, ecdsa-with-SHA256 needs EC P-256) |
| `alg.mgf1`, `alg.salt_length` | PSS MGF1 hash ≠ hash, or saltLength present and ≠ hLen |
| `alg.ecdsa_hash` | ecdsa-with-SHA256 answering a session whose hash is not SHA-256 |
| `alg.mismatch` | wanted algorithm (acsp / `expectedAlgorithm`) ≠ response algorithm; ecdsa-with-SHA256 is always accepted in place of an RSA one (legacy EC credential) |
| `alg.hash_mismatch` | response hash ≠ wanted hash |
| `auth.callback_url` | `signature.initialCallbackUrl` present and neither `""` nor the RP's callback; or Web2App/App2App and ≠ the RP's callback |
| `auth.signature` | ACSP_V2 signature does not verify (§acsp payload) |
| `sign.digest_length` | decoded digest length ≠ hash length |
| `sign.signature` | prehashed signature over `digest` does not verify |
| `revocation.revoked`, `revocation.unknown` | reserved for revocation checks (not used by rp-validate/1) |

Algorithm rules: `rsassa-pss` uses MGF1 with the same hash and salt length = hash length; `shaNNNWithRSAEncryption` is
PKCS#1 v1.5; `ecdsa-with-SHA256` is ASN.1 DER (r, s) over P-256 — **not** IEEE P1363. Auth signs HASH(payload); sign
signs the given digest (prehashed). The signed `initialCallbackUrl` is the response value when present (`""` for QR /
Notification), else the RP's callback.

Chain rule (fail-closed, owner decision 2026-11-26): build the path yourself (do not use OS chain engines); for every
certificate on the path reject critical extensions outside `{2.5.29.14, .15, .17, .19, .30, .31, .32, .35, .37,
1.3.6.1.5.5.7.1.1}`; reject any CA (anchor included) that has nameConstraints (2.5.29.30), critical or not; if
several paths exist, any fully valid one succeeds. Certificate policies are not evaluated.

Levels: qcStatements present → QcCompliance absent = ADVANCED, with QcSSCD = QSCD, else QUALIFIED. Absent → auth
(ACSP_V2) leaf with KeyUsage keyEncipherment, or EKU clientAuth+emailProtection with policy 2.16.496.1.101.1.2.8 →
QUALIFIED; otherwise ADVANCED. Effective = the response's `cert.certificateLevel` if known and not higher (else error);
unknown/missing = the certificate's.

Test PKI (`pki/`): `01-root` → `02-national` → `04-eid` (pathLen 0, the only allowed issuer SKI) issues the citizen
leaves; `05-other` (alien issuer under 02); under 02 also `ca-name-constraints` (permitted DNS `example.test` — satisfied
by the leaves, rejected anyway), `ca-unknown-critical`, `ca-critical-inhibit-any-policy` (critical 2.5.29.54),
`ca-eku-server-auth`, `ca-expired`; `ca-below-pathlen-zero` under 04. Leaves `leaf-<name>.pem` where `<name>` is the
generator's profile name (auth = P-CITIZEN-AUTH, sign = P-CITIZEN-SIGN, token-auth-ec = P-CITIZEN-AUTH-TOKEN, …).

## wire

`wire/cases.json`: `{version: "wire/1", client: {baseUrl, rpUUID, rpName, apiSecret, defaultCertificateLevel}, cases}`.
Build the client from `client`, inject an HTTP transport that answers every request with the case's `response`, invoke
`call`, then check the captured request and the returned value.

- `call.method` — SDK operation (TS camelCase names; map to your casing): `auth.notificationByEtsi(id, interactions,
  options)`, `auth.notificationByDocument(documentNumber, …)`, `auth.deviceLinkAnonymous(interactions, options)`,
  `auth.deviceLinkByEtsi(id, …)`, `sign.digestByEtsi(id, digest, interactions, options)`, `sign.digestByDocument`,
  `sign.textByEtsi(id, text, …)`, `sign.deviceLinkByEtsi`, `sign.deviceLinkByDocument`, `sign.digestForSigner(signer,
  digest, interactions, options)`, `sign.deviceLinkForSigner`, `sign.certificateChoiceByEtsi(id, options)`,
  `sign.certificateChoiceDeviceLink(options)`, `session.poll(sessionId, serverPollMs)`. `call.args` holds the
  arguments by those names; `options` keys: `certificateLevel`, `callbackUrl`, `onBehalfOf`, `signatureAlgorithm`,
  `hashAlgorithm`, `fileName`; `signer`: `documentNumber`, `certChoiceSessionId`.
- `request` — `method`; `path` = path + query exactly as sent (percent-encoded UTF-8, e.g. Cyrillic ids);
  `headers` — `Authorization` exact, `Content-Type` compared by media type only (parameters such as `charset` ignored);
  other headers are not checked. `body` — compared **semantically** (parsed JSON, key order free, no extra or missing
  keys). `volatile` — JSON Pointer → format of a value the SDK generates randomly; in `body` that value is the string
  `"$volatile"`. `base64:64` = standard base64 of exactly 64 random bytes. Check the format, then compare the rest.
- `response` — `status`, optional `headers`, JSON `body` to return (`Content-Type: application/json`).
- `expect` — either `{"error": {class, status, code, retryAfterSeconds?}}` (`class` ∈ `ApiError`,
  `AuthenticationError` (401), `ForbiddenError` (403); `code` = the body's `code`, `""` when absent) or a result:
  - `type: "notification"`: `sessionId`, `vc`, `rpChallenge` (`""` for sign / certificate choice), `acsp` (auth) or
    `null`, `sign` {`digest`, `hashAlgorithm`, `signatureAlgorithm`, `relyingPartyName`, `interactions`,
    `initialCallbackUrl`} or `null`, `expiresAt` (only present when the response carried `expiresAt`; otherwise the
    SDK computes it from the clock and it is not compared).
  - `type: "deviceLink"`: the same plus `sessionToken`, `sessionSecret`, `deviceLinkBase`, `sessionType`
    (`auth`/`sign`/`cert`); for `cert` also `relyingPartyName` and `callbackUrl` (`""` = none).
  - `type: "session"`: `session` = the parsed result (below).
  - A string `"$request:<pointer>"` means "equal to that value of the request body actually sent" (used for
    `rpChallenge`).

Parsed session (`session.poll`): `state`, `endResult`, `documentNumber`, `certificateDerB64`, `certificateLevel`,
`signatureValueB64`, `signatureAlgorithm`, `signatureProtocol` (top-level, else `signature.signatureProtocol`),
`serverRandom`, `userChallenge`, `flowType`, `interactionTypeUsed`; for these string fields `null` ≡ absent ≡ `""`.
`initialCallbackUrl` distinguishes `null` (field absent — old CA) from `""`. `signatureAlgorithmParameters` = `null`
unless `hashAlgorithm` is non-empty, then `{hashAlgorithm, saltLength?}` (other members not compared). `onBehalfOf` =
`null` unless `orgEtsi` non-empty, then `{orgEtsi, orgName, role, rightType, roleLabel?, rightTypeLabel?}`. `person` =
`null` when no non-empty member, else only non-empty strings and non-zero `geID`. `tokenCertificate` = `null` unless
`status` non-empty, then `{status, errorCode?, authSerialHex?, signSerialHex?}`.

## interactions

`interactions_golden.json` `cases[]`: `interactions` (objects with `type`, optional `displayText60`,
`displayText200`), `json` (the exact UTF-8 string), `base64` (= base64 of `json`). Byte-exact rules (JavaScript
`JSON.stringify` of the array): members in the order `type`, `displayText60`, `displayText200`; absent members are
omitted (never `null`/`""`); no whitespace; escape only `"`, `\`, and U+0000–U+001F (`\b \f \n \r \t`, others
`\u00XX` lowercase hex); `<`, `>`, `&`, `'`, `/`, non-ASCII, U+2028/U+2029 and astral characters are written raw (UTF-8).
.NET `System.Text.Json` and Java libraries escape some of these — use a dedicated writer.

## acsp

`acsp_v2.json` `cases[]`: `params` {`schemeName` (`""` → `smart-id`), `serverRandom`, `rpChallenge`,
`userChallenge`, `relyingPartyName`, `brokeredRpName`, `interactions`, `interactionTypeUsed`, `initialCallbackUrl`,
`flowType`}, `hashAlgorithm`, `payload` (exact UTF-8 string), `digestB64`. Payload = `scheme|ACSP_V2|serverRandom|
rpChallenge|userChallenge|b64(UTF-8 relyingPartyName)|b64(UTF-8 brokeredRpName)|b64(SHA-256(interactions string))|
interactionTypeUsed|initialCallbackUrl|flowType`; empty fields keep their `|` separators. The first case is the
Smart-ID documentation vector (SHA-512 → `pKOjbNl/…DfKg==`).

## ocsp

`ocsp/cases.json` `cases[]`: `now`, `certificate` / `issuer` (PEM paths), `http` (replay map), `expect` {`status`,
`errorKind`?}. Run the SDK's OCSP revocation checker (Go `NewOCSPChecker`, TS `ocspRevocationChecker`) with the clock
at `now`, a fresh cache, and an HTTP client that answers from `http`: key `"<METHOD> <URL>"` (the responder URL from
the certificate's AIA, `POST`), value {`status`, `contentType`, `bodyB64`}; any other request → 404. The request body
is not compared (CertID hash choice is the SDK's).

`status`: `good`, `revoked` (also for OCSP `unknown` — the issuer never issued that serial), or `unknown` (no
acceptable answer; the validator's revocation mode decides). Acceptance rules: signed by the issuer, or by a delegated
responder certificate issued by the issuer with id-kp-OCSPSigning valid at `now` (embedded in the response); a response
that embeds the issuer itself is issuer-signed; the single response is for the leaf's serial; `thisUpdate ∈ [now − 48 h,
now + 5 min]`; `nextUpdate` absent or not before `now`; body ≤ 16 KiB; HTTP 200 only, no redirects. `errorKind`
(optional, for SDKs that classify like Go `OCSPError.Kind`): `signature`, `invalid`, `http_status`,
`responder_status`, `parse`, `network`, `timeout`, `no_responder`, `no_issuer`.

## eidlogin

`eidlogin/scenarios.json` drives the login-button backend (Go `eidlogin.Handler`, TS `createEidLogin`) over HTTP with a
fake RP-API. `{config, upstream, scenarios}`; a scenario may override `config` keys and prepend `upstream` rules.

- `config`: client `rpName`, `rpUUID`, `apiSecret`; handler `callbackUrl` (`""` = Web2App off), `successRedirect`,
  `failureRedirect`, `ttlSeconds`, `pollMs`, `pushFloorMs` (0 = off), `cookieName`, `revocation: "disabled"`, `decoy`,
  `recordRateLimitKeys` (install an extra rate-limit hook that records every key and allows it). The default rate
  limits stay on (start: 20 / 60 s per client IP; push: 3 / 60 s per normalised id). The client IP is the request's
  `ip` (absent = unknown → no start limit). Trust: SDK default without anchors. `onSuccess` returns redirect
  `/dashboard`. The handler is mounted at `/auth/eid/{start,status,callback}`; requests use the host
  `https://rp.conformance.test`.
- `upstream` rules (fake RP-API): first match wins on `method` and `path` (exact, query ignored) or `pathPrefix`;
  answer `status` with `body` (JSON) or `bodyText` and `contentType` (default `application/json`);
  `expiresAtInSeconds` adds `expiresAt` = real now + N s (RFC 3339, seconds). No match → 404 `{"error":"not found"}`.
  A step's `upstream` rules are prepended for that step and every later step.
- `steps[]`: `request` {`method`, `path` (with query), `headers`, `json` (sent with `Content-Type:
  application/json`) or `text` (raw, no content type), `cookieFrom` (send `<cookieName>=<value>` from step N's
  Set-Cookie), `ip`}; `repeat` N sends it N times, each must meet `expect`; `expect`:
  - `status`; `json` — subset match of the JSON body; `jsonKeys` — exact key set; `sameKeysAs: N` — same key set as
    step N; `location` — Location header; `headers` — exact values;
  - `setCookie` — the `<cookieName>` Set-Cookie: `value`, `attributes` (`Path`, `Max-Age` strings; `HttpOnly`,
    `Secure`: `true` = flag present; `SameSite`), or `cleared: true` (empty value, `Max-Age=0`); `noSetCookie: true`.
  - Matchers anywhere a value is expected: `{"$re": "…"}` (on the string form), `{"$range": [a, b]}` (number),
    `{"$sameAs": "N.json.<key>"}` (string form equal to step N's JSON member). Numbers compare by value.
- `events` (when present): the exact ordered list of audit events (`OnEvent` / `onEvent`): `kind`, optional
  `sessionId` (`null` ≡ `""`), `meta` subset (`mode`, `decoy`, `reason`, `endResult`, `pushKey` = 32 lowercase hex,
  never the id number).
- `rateLimitKeys`: exact ordered list of keys passed to the recording hook (`start:<ip>`, `push:<normalised id>`).

Not covered here (timing and real signatures): the push response floor and the OK path with a real ACSP signature —
those stay in each SDK's own tests.
