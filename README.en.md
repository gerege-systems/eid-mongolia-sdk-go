[Монгол](README.md) · English · [中文](README.zh-CN.md)

# eid-mongolia-sdk-go

**eID Mongolia** relying-party SDK for Go — authenticating citizens with their phone and having them make legally valid electronic
signatures (qualified signature), and the backend of the "Log in with eID" button. RP-API v3, Smart-ID compatible.
Functionally identical to the TypeScript version ([gerege-systems/eid-mongolia-sdk](https://github.com/gerege-systems/eid-mongolia-sdk)).
Full documentation: <https://developer.eidmongolia.mn/#overview>.

> The SDK runs on the **backend**: every call is authenticated with the API secret (`rp_sk_…`). Never expose the secret or the `SessionSecret`
> to the browser/phone — the browser only sees the link / QR / button your backend provides.

- Go ≥ 1.25. `eid` and `eidlogin` import the standard library + `golang.org/x/crypto/ocsp` (OCSP revocation); `pades` (PDF)
  uses `github.com/gerege-systems/pdf` (a fork of digitorus/pdf v0.1.2 with the DoS fix), digitorus pkcs7, timestamp,
  `golang.org/x/crypto`, `golang.org/x/text`.
- Packages: `eid` (RP-API, device link, validator, PDF registration), `eidlogin` (`github.com/gerege-systems/eid-mongolia-sdk-go/eidlogin`
  — the net/http handler for the "Log in with eID" button),
  `pades` (client-side PAdES — the PDF does not go to eID's server; the reference for the native SDKs).

## Installation

```bash
go get github.com/gerege-systems/eid-mongolia-sdk-go@v0.31.0
```

`pades` imports the patched PDF parser (`github.com/gerege-systems/pdf`) directly, so no `replace` is needed.
The `replace github.com/digitorus/pdf => github.com/craftzbay/pdf …` line from READMEs up to v0.21.x is no longer needed by the SDK
(since v0.22.0 the SDK does not import `github.com/digitorus/pdf`) — please remove it. However, if your own code imports `github.com/digitorus/pdf`
or `github.com/digitorus/pdfsign`, keep the line so that they stay patched.

```go
import (
	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
	"github.com/gerege-systems/eid-mongolia-sdk-go/eidlogin"
)
```

## 1. Registering an RP

An RP is registered by an eID Mongolia operator — submit your request to <eIDsupport@gerege.com>. The application API
(`POST https://ca.eidmongolia.mn/v3/rp-applications`, discovery's `registration.apply`) is currently under maintenance — it returns 503
`rp_applications_maintenance` (checked on 2026-10-15). After approval you are issued a
**relyingPartyUUID** and an **API secret** (`rp_sk_…`); the secret is shown **only once**. Required
information (organization, purpose `AUTH`/`SIGN`, `callbackHosts`…):
<https://developer.eidmongolia.mn/#registration>.

## 2. "Log in with eID" — a single button (`eidlogin`)

The pattern used by Smart-ID RPs: **one button** in the browser, all eID calls on your backend (with the API secret).
`eidlogin.Handler` (net/http) is a ready-made flow that uses only the RP-API from §3.1/§3.2 (device link v3, push, `Validator`);
the browser button is the TS SDK's Web Component `<eid-login-button>` (`@gerege-systems/eid-mongolia-sdk/button`) — the response
shape is identical to the TS `createEidLogin`.

| | Request | Response |
|---|---|---|
| `POST /auth/eid/start` | `{"mode":"qr"}` or `{"mode":"push","idCode":"УБ12345678"}` (JSON required) | `{mode, vc, qr?, expiresIn}` + `Set-Cookie: __Host-eid_login` |
| `GET /auth/eid/start?mode=web2app` | mobile browser (button navigation) | `302` → eID app (Web2App) |
| `GET /auth/eid/status` | cookie | `PENDING` (`vc`, `expiresIn`, + a new `qr`) · `WAIT_CALLBACK` · `OK` (`redirect`, `data`) · `FAILED` (`error`) · `EXPIRED` |
| `GET /auth/eid/callback` | the app returns: `?sessionId&userChallengeVerifier` | `303` → `Success.Redirect` / `SuccessRedirect`, on error `FailureRedirect?eid_error=<code>` |

The eID server always normalizes the Web2App return path to `/auth/eid/callback`, so mount under `/auth/eid/`:

```go
c, _ := eid.NewClient(eid.Config{
	Credentials: eid.Credentials{RPUUID: uuid, RPName: "Internet Bank", APISecret: secret},
	// Root (01) is the trust anchor; the intermediates 02 → 03 → 04 are built into the SDK (eid.CitizenIntermediatesPEM, the default).
	Trust: eid.TrustConfig{TrustAnchorsPEM: []string{eid.NationalRootCAPEM}},
})
login, err := eidlogin.New(eidlogin.Config{
	Client:      c,
	CallbackURL: "https://bank.example.mn/auth/eid/callback", // the host must be in callbackHosts; required for the phone flow
	OnSuccess: func(w http.ResponseWriter, r *http.Request, id *eidlogin.Identity) (*eidlogin.Success, error) {
		// id.ETSI (PNOMN-…) — identify the user BY THIS; id.GivenName/Surname (Latin), id.Person (Cyrillic, if present)
		// id.SessionID, id.DocumentNumber, id.Certificate — for the next steps (signing, linking the certificate)
		u, err := users.FindOrCreateByETSI(r.Context(), id.ETSI)
		if err != nil {
			return nil, err
		}
		sid, err := sessions.Create(r.Context(), u.ID) // a NEW session (session fixation)
		if err != nil {
			return nil, err
		}
		http.SetCookie(w, &http.Cookie{Name: "app_session", Value: sid, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		return &eidlogin.Success{Redirect: "/dashboard"}, nil
	},
	ClientIP: eidlogin.ForwardedClientIP(1), // behind a single nginx/LB hop; without a proxy use eidlogin.RemoteAddrIP
	// Store: redisStore,        // for multiple instances (default — process memory)
	// RateLimits: map[string]eidlogin.RateRule{"start": {Max: 20, Window: time.Minute}}, // merged with the defaults (push stays 3/min)
	OnEvent: func(ctx context.Context, kind eidlogin.EventKind, sessionID string, meta map[string]any) {
		audit.Record(ctx, "auth.eid_"+string(kind), sessionID, meta) // your audit
	},
	// AuditKey: []byte(os.Getenv("EID_AUDIT_KEY")), // keep pushKey stable across instances/restarts
})
if err != nil {
	log.Fatal(err)
}
mux.Handle("/auth/eid/", login)
```

In the browser:

```html
<script type="module" src="https://cdn.jsdelivr.net/npm/@gerege-systems/eid-mongolia-sdk@0.26.0/dist/button.js"></script>
<eid-login-button start-url="/auth/eid/start" status-url="/auth/eid/status" lang="mn"></eid-login-button>
```

On desktop a dialog (the QR refreshes every second + push by registry number); on a phone the eID app opens directly. On success, the
`eid-login-success` event and a redirect to `redirect`. Colours: `--eid-*` (at any level of the page, for both light and dark),
`--eid-<name>-dark` (takes precedence for dark only) — the full list is in the TS SDK's README §1a.

**Security.**

- `SessionToken`, `SessionSecret` and `rpChallenge` stay on the server (`Store`); the browser only gets an HttpOnly, Secure, SameSite=Lax cookie
  (`<sessionId>.<binding>`, SHA-256 in the store). Status and callback respond only to the **browser that started the login** — a callback
  URL opened in a different browser (even with the verifier) is not accepted (login CSRF).
- The `start` POST requires JSON (cross-origin preflight), and `Sec-Fetch-Site: cross-site` → 403.
- `OK` is returned only when `Validator.ValidateAuth` succeeds: QR → `FlowQR`, push → `FlowNotification`, phone → `FlowWeb2App` +
  `userChallengeVerifier`. A Web2App session is not finished by polling (`WAIT_CALLBACK`). `OnSuccess` runs only once per session
  (`Store.Delete` is atomic — Redis `DEL`).
- `Success.Data` goes to the browser — do not put secrets in it.
- **Registry-number oracle protection (decoy + minimum duration, on by default).** When eID rejects a push because of the number
  (eID's own JSON 4xx — unknown / unusable number), the handler gives a response **identical** to a real push: `{mode, vc
  (random 5 digits — same shape as eID's), expiresIn}`, same cookie; `status` holds `PENDING` for the `Poll` duration without asking eID,
  then `EXPIRED` after the TTL — indistinguishable from a citizen who did not pick up their phone (a real push's CA `TIMEOUT` also becomes `EXPIRED`). Every push start response (real, decoy, 502)
  takes at least `PushFloor` (default 1 s) — so the decoy cannot be told apart by timing. The limits (`push:<pushKey>`, `start:<ip>`)
  also apply to the decoy; 429 and 400 (`invalid_id` — a format error, independent of registration) have no floor.
  eID's 5xx, connection errors, non-JSON 4xx (a proxy in front of eID, e.g. an mTLS rejection), 401/403 (the RP's secret/permission) and 429 are
  **not decoyed** — `502 eid_unavailable` / `429` (the eID portal's behaviour: hiding an outage behind a decoy would leave the citizen with an endless spinner;
  these do not depend on the number, so they are not an oracle). To disable: `DisableDecoy`, `DisablePushFloor` — **WARNING:** then
  `/start` tells anyone, unauthenticated, "whether this registry number is registered in eID"; internal/test environments only.
- **The lifetime (`Config.TTL`, default 2 min) never exceeds the CA's session.** QR / Web2App: `expiresIn`, cookie
  `Max-Age`, and the store = min(`TTL`, the CA start response's `expiresAt` − now). Push (real and decoy **identical**): min(`TTL`,
  discovery `sessionTtl.auth`) — since a decoy has no CA response, it uses discovery (`c.Auth.SessionTTL`,
  10 min cache inside the handler; retry after 1 min if the fetch fails) rather than the CA's `expiresAt` — so a timing difference cannot become an oracle. Older CA
  (no `sessionTtl` in discovery): the next decoy takes the value observed from a real push's `expiresAt` (±1 s); before the first
  real push, `TTL`.
- **Certificate revocation (OCSP, on by default).** After `ValidateAuth` and before `OnSuccess`, the citizen's certificate is checked against
  the OCSP responder listed in its AIA (`Config.Revocation`, nil = `eid.NewOCSPChecker`; the response must be signed by the issuer or
  its OCSPSigning responder, for this serial, thisUpdate ≤ 48 h, and a good result is cached for min(5 min, NextUpdate)).
  `revoked`, and also `unknown` (the issuer did not issue this certificate) → `FAILED` / `VALIDATION` (not 500), and `OnSuccess` is not called.
  With no response (2 s timeout, 5xx, no AIA, a failed check): `RevocationMode` "" = soft-fail — allow it and write a Warn log,
  `Identity.Revocation = unchecked` (the eID portal's `EID_OCSP=soft`: if the CA's responder goes down not every citizen is locked out; and the CA could reach the phone
  seconds earlier when the session was confirmed); `eid.RevocationHardFail` → `FAILED` / `VALIDATION`.
  `DisableRevocation` — **WARNING:** logins succeed with a revoked (stolen phone) certificate.
- **Audit — `Config.OnEvent(ctx, kind, sessionID, meta)`** (synchronous): `push_sent` (meta `decoy` — only in your audit,
  never to the browser), `push_limited`, `refused` (the citizen declined), `expired` (TIMEOUT / not found in eID), `unverified`
  (`reason`: `validation` | `revoked` | `revocation_unavailable`), `flow_refused` (a Web2App callback in a different browser), `success`
  (`flow`, `revocation`), `failed` (other `endResult`). meta carries `mode`; tokens/secrets and registry numbers are never included — for push,
  `pushKey` = the 32 hex of HMAC-SHA256(`AuditKey`, number) (random per process if `AuditKey` is nil).
- BEFORE `OnSuccess` the tx is atomically deleted from the store (a one-time guarantee) — do not read from the store inside `OnSuccess`;
  everything you need is in `Identity` (`SessionID`, `DocumentNumber`, `Certificate`, …).

**Client IP** (the `start:<ip>` limit) — `Config.ClientIP`. Behind trusted reverse proxies, `eidlogin.ForwardedClientIP(n)`:
the value **n-th from the right** in `X-Forwarded-For` (n = the number of your proxies), `X-Real-IP` if there is no XFF, and `""` if there are too few hops.
Without a proxy, `eidlogin.RemoteAddrIP`. If nil, no per-IP limiting is applied (`New` writes a one-time Warn). The same rules as the TS SDK's
`trustProxy` / `getClientIp`.

**Rate limiting.** Keys: `start:<ip>` (if ClientIP is provided; IPv6 → its `/64` prefix, an empty ClientIP → the shared `start:unknown` bucket), `push:<pushKey>` (since v0.32.0 the audit HMAC, never the id number); when rejected: 429 + `Retry-After: 60`.
The default `eidlogin.DefaultRateLimit()` = `{"start": {Max: 20, Window: time.Minute}, "push": {Max: 3, Window: time.Minute}}`
— 20 starts per minute from one IP (since v0.6.0; if `ClientIP` is provided), 3 notifications per minute to one number (MFA fatigue). The in-memory
limiter holds ≤ 10 000 keys per type (`RateRule.MaxKeys`): when full, it purges expired windows, and if it is still full it counts **new** keys in
one shared overflow bucket (since v0.32.0; before: 429) — existing counters are never evicted, so the limit cannot be bypassed by filling it with many IPs/numbers.
`NewMemoryStore()` is likewise ≤ `eidlogin.MemoryStoreMax` (10 000): when full, start returns 503 `{"error":"busy"}`
(`eidlogin.ErrStoreFull`) and does not delete logins already in progress. With multiple instances, use a Redis store/limiter.

- `Config.RateLimits map[string]RateRule` — **merged** with the defaults: a type you provide (`"start"` | `"push"`) overrides the default,
  one you omit keeps its default. `RateRule{Max, Window}` — a sliding window in process memory; `RateRule{Func: …}` — your own
  (Redis etc.); `RateRule{}` — do not limit that type. Any other key → `New` returns an error.
- `Config.RateLimit func(ctx, key) bool` — for all keys, **added on top of** the default limits (both must allow).
  To relax/replace a default, pass that type through `RateLimits`.

```go
lim := eidlogin.DefaultRateLimit()                                  // if writing it out explicitly
lim["start"] = eidlogin.RateRule{Func: redisAllow}                  // push stays 3/min
// lim["start"] = eidlogin.RateRule{}                               // if start is rate-limited in nginx/gateway
lim["push"] = eidlogin.RateRule{Func: redisAllowPush}               // multiple instances: replace push with Redis
cfg.RateLimits = lim
```

The TS SDK's `rateLimit` (`{ start?, push? }` | a function, `defaultRateLimit`) — the same semantics.

**Redis store** (the SDK has no extra dependency — for example `github.com/redis/go-redis/v9`):

```go
type redisStore struct{ rdb *redis.Client }

func (s redisStore) key(sid string) string { return "eid:login:" + sid }

func (s redisStore) Get(ctx context.Context, sid string) (*eidlogin.Tx, error) {
	b, err := s.rdb.Get(ctx, s.key(sid)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis get: %w", err)
	}
	var tx eidlogin.Tx
	if err := json.Unmarshal(b, &tx); err != nil {
		return nil, fmt.Errorf("redis tx: %w", err)
	}
	return &tx, nil
}

func (s redisStore) Set(ctx context.Context, tx *eidlogin.Tx, ttl time.Duration) error {
	b, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key(tx.SessionID), b, ttl).Err()
}

// DEL is atomic — of two concurrent status calls only one invokes OnSuccess.
func (s redisStore) Delete(ctx context.Context, sid string) (bool, error) {
	n, err := s.rdb.Del(ctx, s.key(sid)).Result()
	return n == 1, err
}
```

The Tx holds `SessionSecret` (the material for assembling the QR) — keep Redis closed off from the network, with TLS/AUTH.

**Minimum eID app version.** The `flowType` binding (device link v3) and Web2App's `userChallengeVerifier` start from
**iOS 2.2.3 (build 59)** and **Android 2.2.3 (versionCode 60)**. The eID server fully removed legacy links on 2026-10-07
(for a session without v3 the phone returns `DEVICE_LINK_REQUIRED`) and forces a minimum version through `/mobile/app-config`:
Android ≥ 70 from 2026-10-07, and as of 2026-10-20 iOS ≥ 2.2.8, Android ≥ 91
(`curl https://ca.eidmongolia.mn/mobile/app-config`). Every app able to sign therefore supports these. Sources:
the eID CA's `docs/DEVICE_LINK_V3.md` §5, §7; changelog `2026-10-02-ios-min-version-2-2-3`, `2026-10-07-android-min-70`.

## 3. RP-API client

```go
c, err := eid.NewClient(eid.Config{
	// BaseURL defaults to https://rp.eidmongolia.mn (RP-API, no /v3) — an RP with mTLS uses this host too
	Credentials: eid.Credentials{
		RPUUID:    os.Getenv("EID_RP_UUID"),
		RPName:    "Internet Bank", // subsystem name, ≤ 120 characters (the CA truncates anything longer)
		APISecret: os.Getenv("EID_SECRET"),
	},
	Trust: eid.TrustConfig{
		TrustAnchorsPEM: []string{eid.NationalRootCAPEM}, // Mongolian National Root CA (01) — REQUIRED in production
		// IntermediatesPEM nil = eid.CitizenIntermediatesPEM (02 MDDC → 03 Gerege → 04 eID Mongolia Issuing CA)
	},
})
```

Every call takes a `context.Context` (cancellation, deadline); the default timeout for each call is `Config.Timeout` (15s),
a long-poll uses its own length, and `PDF.RegisterSignature` uses `Config.PDFTimeout` (default 80s — the CA verifies the CMS + TSA + LTV;
the TS SDK has had the same 80 s `pdfTimeoutMs` since 0.19.0). The source of the intermediate CAs: <https://developer.eidmongolia.mn/#verification>.

### 3.1. Authentication — push

```go
s, err := c.Auth.NotificationByEtsi(ctx, "PNOMN-12345678", // ETSI / registry number / civil ID number (the server recognizes it)
	[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "Log in to Internet Bank"}}, nil)
show(s.VC) // a 5-digit verification code — NOT a PIN, display only

// long-poll; waits until the session expires (ExpiresAt + 15 s; discovery sessionTtl if nil, otherwise 600 s).
// The CA turns an expired session into COMPLETE/TIMEOUT; if MaxWait is given, it cuts the wait off and returns RUNNING without an error.
r, err := c.Session.WaitForResult(ctx, s.SessionID, &eid.WaitOptions{ExpiresAt: s.ExpiresAt})
who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{ExpectedFlowType: eid.FlowNotification})
if err != nil {
	return err // *eid.SessionFailedError (USER_REFUSED, TIMEOUT…) or *eid.ValidationError — DO NOT TRUST
}
if err := c.Validator.CheckRevocation(ctx, who.Certificate); err != nil { // if TrustConfig.Revocation is configured
	return err
}
log.Println(who.DocumentNumber, who.Subject.SerialNumber, who.Subject.GivenName, who.Subject.Surname)
```

### 3.2. QR and same-device — device link v3

The citizen scans the **QR** on another screen with their phone, or, if the RP's site was opened on the **same phone** as the eID app, a button
opens the app. **For the same device, use the Web2App (device link v3) flow** — pressing the button in the phone's browser opens the app directly,
and after confirmation it returns to your `CallbackURL` with a `userChallengeVerifier`. (From an RP's native app,
App2App.) The legacy `/dl?sessionId&vc` link was removed from the server on 2026-10-07 — it does not exist in the SDK.

```go
// backend — start the session and store the whole response ON THE SERVER (SessionToken/SessionSecret/ReceivedAt/ACSP)
s, err := c.Auth.DeviceLinkAnonymous(ctx,
	[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "Log in to Internet Bank"}},
	&eid.AuthOptions{CallbackURL: "https://bank.example.mn/auth/eid/callback?tx=" + txID}) // if showing a button; host = callbackHosts
store.Put(s.SessionID, s) // ONLY SessionID and VC go to the browser

link := func(s *eid.DeviceLinkSession, t eid.DeviceLinkType) (string, error) {
	return eid.BuildDeviceLink(eid.DeviceLinkInput{
		DeviceLinkBase: s.DeviceLinkBase, DeviceLinkType: t,
		SessionToken: s.SessionToken, SessionSecret: s.SessionSecret,
		SessionType: eid.SessionAuth, Lang: "mon", ReceivedAt: s.ReceivedAt,
		RPChallenge: s.ACSP.RPChallenge, RelyingPartyName: s.ACSP.RelyingPartyName,
		Interactions: s.ACSP.Interactions, InitialCallbackURL: s.ACSP.InitialCallbackURL, // not part of authCode for QR
	})
}

// GET /eid/qr?sessionId=… — the browser calls this every second and redraws the QR (a QR is valid for ~20 s)
http.HandleFunc("GET /eid/qr", func(w http.ResponseWriter, r *http.Request) {
	s := store.Get(r.URL.Query().Get("sessionId")) // check that it belongs to the caller's own browser session
	l, err := link(s, eid.LinkQR)
	if err != nil {
		http.Error(w, "session ended", http.StatusGone)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"link": l})
})
// on a phone: the button's href = link(s, eid.LinkWeb2App) (built once)
```

To push over SSE/WebSocket, use `eid.TickQRDeviceLink(ctx, input, time.Second, send)` — it emits a link immediately, then every second;
stop it by cancelling `ctx`.

**Always check the type you showed (relay protection):**

```go
// QR page → a result completed via polling
who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{ExpectedFlowType: eid.FlowQR})

// Web2App button → after the callback (?userChallengeVerifier=…) arrives
who, err = c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{
	ExpectedFlowType:      eid.FlowWeb2App, // eid.FlowApp2App if the button is inside the RP's app
	UserChallengeVerifier: callback.Query().Get("userChallengeVerifier"),
})
```

On one page with both a QR and a button: ONE session (with `CallbackURL`); check a result that arrived via the callback as `Web2App`/`App2App`,
and one that arrived by polling as `QR`.

### 3.3. Signature (digest)

```go
digest := eid.SHA256Base64(docBytes)
s, err := c.Sign.DigestByEtsi(ctx, "PNOMN-12345678", digest,
	[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "Sign the loan agreement"}}, nil)
show(s.VC)
r, err := c.Session.WaitForResult(ctx, s.SessionID, nil)
sig, err := c.Validator.ValidateSign(r, digest, eid.SHA256) // against the digest
// SignOptions.FileName — the document name, shown on the CA's /verify page and in the citizen's history (optional)

// if started via device-link / push, check the flow (same as ValidateAuth; a mismatch gives *ValidationError)
sig, err = c.Validator.ValidateSign(r, digest, eid.SHA256, eid.ValidateSignOptions{ExpectedFlowType: eid.FlowQR})
```

With RAW_DIGEST_SIGNATURE, `flowType` is not part of the signature (only the digest is signed) — this is a check against the RP-API response.

**QR / Web2App / App2App** — `c.Sign.DeviceLinkByEtsi` / `DeviceLinkByDocument` (Web2App/App2App when `SignOptions.CallbackURL` is given);
the link is built with `eid.BuildDeviceLink(s.LinkInput(eid.LinkQR, "mon"))` (also for auth/cert sessions).
Store `s.Sign` (`SignContext`: digest, hash, algorithm, interactions, callback) on the server together with the session.

**`ExpiresAt`** — the moment the session ends: the `expiresAt` (RFC 3339) in the CA's session start response (for auth / sign / certificate-choice
alike, since 2026-10-14). With an older CA (no field), for sign / certificate-choice the SDK computes it — the CA's default 600 s
(`eid.DefaultSignSessionTTL`; a CA admin can set 60–1800 s → `Config.SignSessionTTL`), and for auth it is zero. The final truth is `GET /session`
(`TIMEOUT`). The live value of the CA's configuration: `c.Auth.SessionTTL(ctx)` — discovery `sessionTtl` (`Auth`, `Sign`; 0 for an older CA).

**Session start errors** (`*eid.APIError`, via `errors.Is`): `eid.ErrNoSigningCertificate` — 409 `NO_SIGNING_CERTIFICATE`
(sign / certificate-choice start: the citizen has no active device / valid signing certificate;
no session was created); `eid.ErrCertChoiceInvalid` — 409 `CERT_CHOICE_INVALID` (the linked sign's certificate-choice is invalid /
stale / already used → start again); `eid.ErrRequestInvalid` — 400 `REQUEST_INVALID` (e.g. `linkedSessionID` missing in linked).

**Knowing the certificate in advance (client-side PAdES / CMS)** — because the certificate goes into the DTBS (`signingCertificateV2`), do
certificate-choice first, then have the digest signed **on exactly that device (`documentNumber`)**. For a citizen with several phones,
starting by etsi makes a different phone sign, and the signature will not match the certificate.

```go
cc, err := c.Sign.CertificateChoiceByEtsi(ctx, "PNOMN-12345678", nil) // or CertificateChoiceDeviceLink (QR; Web2App/App2App if CallbackURL is given)
r, err := c.Session.WaitForResult(ctx, cc.SessionID, nil)
signer, err := c.Validator.ValidateCertificateChoice(r, cc.SessionID) // Signer{Certificate, DocumentNumber}
dtbs := buildDTBS(signer.Certificate)                                 // 32-byte SHA-256, standard base64
s, err := c.Sign.DigestForSigner(ctx, signer, dtbs, ix, &eid.SignOptions{FileName: "Contract.pdf"}) // linked/{documentNumber}
// QR / Web2App: c.Sign.DeviceLinkForSigner(ctx, signer, dtbs, ix, &eid.SignOptions{CallbackURL: …})
r, err = c.Session.WaitForResult(ctx, s.SessionID, nil)
sig, err := c.Validator.ValidateSign(r, s.Sign.Digest, s.Sign.HashAlgorithm, eid.ValidateSignOptions{
	ExpectedFlowType:    eid.FlowNotification,
	ExpectedAlgorithm:   s.Sign.SignatureAlgorithm, // sha256WithRSAEncryption — a PSS response is rejected
	ExpectedCertificate: signer.Certificate,        // rejected if signed with a different certificate
})
```

`DigestForSigner` / `DeviceLinkForSigner` default to `sha256WithRSAEncryption` + `SHA-256` (the CA's SplitKey RSA signs with the requested
algorithm, PKCS#1 v1.5; the legacy threshold-ECDSA credential is always `ecdsa-with-SHA256` — `ExpectedAlgorithm` accepts it
only with an EC P-256 certificate). If the digest length does not match the hash, the request is not sent.

**Linked signing on the phone (v0.23.0)** — when the citizen is on the RP's site on one phone: if the certificate-choice device link is started with
`CertChoiceOptions.CallbackURL`, a Web2App/App2App link becomes possible (the CA checks the field against the `callbackHosts`
allowlist and normalizes the path to `/auth/eid/callback`; if it is not in the allowlist it is dropped and the session becomes QR-only).
`CertificateChoiceByEtsi` (push) sends no callback. The phone opens the callback only **after the linked SIGN completes**
(the linked SIGN session itself has no callback); the query: the RP's own parameter (e.g. `value=<random>`) unchanged +
`sessionSecretDigest` + `sessionId` (the certificate-choice session), and no `userChallengeVerifier`.

```go
// 1. Start: store value in the browser's cookie.
cc, err := c.Sign.CertificateChoiceDeviceLink(ctx, &eid.CertChoiceOptions{
	CallbackURL: "https://rp.example.mn/auth/eid/callback?value=" + value,
})
link, err := eid.BuildDeviceLink(cc.LinkInput(eid.LinkWeb2App, "mon")) // or LinkApp2App; LinkQR for QR
// 2. Verify the certificate choice, then start the linked sign (DeviceLinkForSigner / DigestForSigner — see the example above).
r, err := c.Session.WaitForResult(ctx, cc.SessionID, nil)
signer, err := c.Validator.ValidateCertificateChoice(r, cc.SessionID)
// 3. At /auth/eid/callback:
//    - whether the query's `value` equals the browser's cookie;
//    - eid.VerifySessionSecretDigest(q.Get("sessionSecretDigest"), cc.SessionSecret) — cc is the server-side stored
//      certificate-choice session (looked up by sessionId); SessionSecret never reaches the browser;
//    - accept the callback ONLY ONCE (reject a second time);
//    - then read the linked SIGN session's result (c.Session.WaitForResult → ValidateSign) and decide.
```

`eid.SessionSecretDigest(secret)` = `BASE64URL-NOPAD(SHA-256(base64-decode(secret)))`; `VerifySessionSecretDigest` compares in
constant time and returns `false` for malformed input. The arrival of the callback does NOT mean the document was signed —
always read the result from the session and check it with `ValidateSign`.

### 3.4. On behalf of an organization

The citizen signs **with their own PIN2 certificate**; eID checks the authority to represent the organization against its own registry (a personal
qualified signature — not an organization seal). Signing a PDF is client-side PAdES — [§7](#7-client-side-pades-pades).

```go
reps, err := c.Organization.GetRepresentations(ctx, "PNOMN-12345678") // the citizen must have logged in within the last 24 hours
s, err := c.Sign.DigestForSigner(ctx, signer, dtbs, ix, &eid.SignOptions{OnBehalfOf: "NTRMN-6235972"})
// r.OnBehalfOf — proof that the SERVER checked the representation (nil = an individual)
```

If `OnBehalfOf` is rejected, the `Code` of `*eid.ForbiddenError` / `*eid.APIError` (`eid.OnBehalfErrorCodes`):
`REPRESENTATION_DENIED`, `REPRESENTATION_PENDING`, `REPRESENTATION_EXPIRED`, `ORG_NOT_ACTIVE`, `SIGNER_UNIDENTIFIED`
(403) · `ORG_NOT_FOUND` (404) · `REPRESENTATION_REVOKED` (403, in `RegisterSignature` and token certificate issuance).

Transient errors — `*eid.APIError.Retryable()` is true; retry after `RetryAfter` (the CA's `Retry-After`, seconds or a date)
(`eid.RetryableCodes`; a 429/503 + `Retry-After` without a code too). `Header` — all the response headers.

A JSON response over 4 MiB gives `*eid.ResponseTooLargeError` (it is not truncated). `GetRepresentations`'s `Raw` — the server's
raw JSON.

**When showing these to a person, use `RoleLabel` / `RightTypeLabel` / `SourceLabel`** (all three in `Representation`; in the session's
`OnBehalfOf` only `RoleLabel` / `RightTypeLabel` — there is no `Source` there) — `Role` (`ceo` / `founder` / `stakeholder`, or the text entered for a
MANAGER), `RightType` (`ADMIN` | `MANAGER`) and `Source` (`REGISTRY` | `MANUAL`) are machine values; do not translate them yourself. Language: `eid.Config{…, Language: "en"}` → an `Accept-Language` on every call; `""` = none sent (the server uses mn).
Empty for an older CA.

### 3.5. The session's person block

```go
r, _ := c.Session.WaitForResult(ctx, s.SessionID, nil)
who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{})
if err == nil && eid.PersonMatchesCertificate(r.Person, who.Subject) {
	// r.Person: FirstName (name), LastName (FATHER'S name), FamilyName (FAMILY name), CivilID, RegNo, BirthDate, Gender, GeID, Nationality (ISO 3166-1 alpha-3, e.g. MNG; optional)
}
// r.Raw — the server's raw JSON (for fields the SDK does not parse)
```

The person block is **not part of** the signature — trust it only after matching it against the certificate's `SERIALNUMBER` (`PNOMN-<civilId>`).

### 3.6. Citizen PKI dashboard (`PKI_READ` permission)

`c.Person.Certificates` · `Devices` · `Activity(ctx, etsi, &eid.ActivityQuery{Flow, Limit, Offset})` · `Summary` ·
`Children` — the citizen must have logged in through your RP within the last 24 hours (otherwise 403). Every response has a `Raw`.

`PersonCertificate` (since v0.5.0) has `IssuedAt` (issued), `RevokedAt` (revoked — REVOKED) and `RevocationReason` (the RFC 5280
name: `keyCompromise`, `superseded`, `cessationOfOperation` …). `Status` is not changed: a row replaced by a renewal/re-registration
is `SUSPENDED` + `RevocationReason: "superseded"`, with `RevokedAt` nil.

A `KeyMedium == "TOKEN"` row has `Organization` (an organizational token; nil for a personal one) and `TokenSerial` — the serial number of the
USB token the certificate was issued to. Do not guess one token's AUTH + SIGN by organization/date — group them by `TokenSerial`
(a row replaced through renewal also carries its own token's number). `""` for MOBILE/HSM rows and older CAs.

### 3.7. USB token

```go
// certificate issuance (TOKEN_ISSUE permission) — the citizen confirms with PIN2 on their phone
in := eid.TokenCertInput{SignerEtsi: etsi, CSRAuth: csrA, CSRSign: csrS,
	TokenSerial: "EP2003-0042A1", OnBehalfOf: ""} // "" = personal token
// BEFORE the push: dryRun with the same input — no session/push is created, error codes are the same as for real
pv, err := c.Token.PreviewCertificate(ctx, in) // if pv.Supersedes is set, warn the citizen and get their consent, then ↓
st, err := c.Token.IssueCertificate(ctx, in)
// st.Supersedes — the previous personal tokens a personal issuance will replace (below); warn the citizen before PIN2
if l, ok := eid.TokenLimitOf(err); ok { /* 409 TOKEN_LIMIT_REACHED: l.Kind, l.Limit, l.Organization */ }
// 409 eid.CodeTokenInUse — the serial belongs to another citizen; 409 eid.CodeTokenScopeChange — a renewal that would change scope (below)
// 400 eid.CodeAppAttestationInvalid — an AppTransaction was sent but is invalid (below)
// … c.Session.Poll → r.TokenCertificate.Status == eid.TokenCertIssued
res, err := c.Token.CertificateResult(ctx, st.SessionID)
err = eid.VerifyTokenCertificates(res, csrA, csrS) // every certificate matches its CSR's key

// signing in with the token (AUTH permission)
ch, err := c.Token.AuthChallenge(ctx)
digest, _ := eid.TokenAuthDigest(ch.RPUUID, ch.Challenge) // the token's CKM_ECDSA → raw r||s
// since v0.6.0 pass the challenge whole (kept by the RP, or returned from the client — the CA matches it by ChallengeID):
// the SDK does not trust the CA's OK alone — it checks r||s against the certificate's key, the RPUUID against its own, and the certificate against Trust
// (chain, issuer, purpose auth) and only then sends it to the CA.
who, err := c.Token.AuthVerify(ctx, ch, authCertDER, rs)

// PDF with a token — client-side PAdES (§7): the token signs the DTBS, with Medium: eid.PDFMediumToken in RegisterSignature
```

**Renewal preserves the scope** (CA 2026-10-16, discovery `tokenCertificate.scopeLockedOnRenewal: true` —
`c.Token.CertificateInfo(ctx)`): if the citizen has an ACTIVE record for the same `TokenSerial`, issuance = renewal; an organizational
token only for that organization (same `OnBehalfOf`), a personal token only as personal. For a different scope, `IssueCertificate`
(or, after confirmation, `CertificateResult`) returns 409 `eid.CodeTokenScopeChange` (`TOKEN_SCOPE_CHANGE`), and the session's
`TokenCertificate.ErrorCode` is the same — there is no override. Changing scope = the citizen revokes the token in the eID app
(`/v3/mobile/tokens/{tokenSerial}/revoke`) and has it issued anew; to the user: "To change the token type (personal/organizational),
revoke the token in the eID app and have it issued again."

**Automatic replacement of a personal token** (CA 2026-10-19, discovery `tokenCertificate.personalAutoSupersede: true`): when the personal
limit is reached, a new personal token with a different `TokenSerial` is not a 409 — `st.Supersedes` (`[]eid.TokenSupersede{TokenSerial}`)
comes back; once the new issuance for the personal token succeeds (PIN2 + certificate), the previous personal token's AUTH + SIGN are revoked as superseded (4).
A rejected / expired issuance does not touch the previous one. Before PIN2: "The certificates of your previous USB token (EP2003-…)
will become invalid." 409 `TOKEN_LIMIT_REACHED` with `kind=PERSONAL` occurs only when `limit=0` (personal issuance closed);
an organizational token (`ORGANIZATION`) remains a hard limit.

**dryRun — a check before the push** (CA 2026-10-19, discovery `tokenCertificate.dryRun: true` —
`CertificateInfo().DryRun`): when `IssueCertificate`'s response has `Supersedes`, a PIN2 push has already gone to the phone —
even if you cancelled on desktop, if the citizen confirms on the phone the old token is replaced. So the flow is: CSR → `c.Token.PreviewCertificate(ctx, in)`
(the same body + `"dryRun": true`; all checks, the same error codes — including `409 TOKEN_ISSUANCE_PENDING` for a pending issuance with a different CSR host;
no session / push / state is created) → if there is `Supersedes`, show a warning and let the citizen agree →
`IssueCertificate(ctx, in)`. The rate limit (RP, citizen) is 20/min and 120/10 min for the RP in total — it does not consume the push's 3/hour. If the response does not come back with `dryRun: true`, `*eid.ValidationError` (an older CA returns 400 for the unknown field).

**App attestation (`AppTransaction`, optional)** (CA 2026-10-19, discovery `tokenCertificate.appTransaction:
"optional"`): the macOS App Store build passes the StoreKit 2 `AppTransaction` JWS (compact) string from the desktop —
`eid.TokenCertInput{…, AppTransaction: jws}`. The CA does not call Apple's servers; it checks offline; if present it must be
valid, otherwise 400 `eid.CodeAppAttestationInvalid` (`APP_ATTESTATION_INVALID`; it does not say which step failed, and no push
goes to the phone). `""` (Windows) = issuance without attestation. Above `eid.MaxAppTransactionBytes` (16 KiB) the SDK does not send and
returns `eid.ErrAppTransactionTooLarge`. Sending the field to an older CA (`CertificateInfo().AppTransaction == ""`) returns 400.

`/token/auth/*` is listed in `/.well-known/eid`'s `endpoints.token.auth_challenge` / `auth_verify` (AUTH permission) —
the contract test checks it like the other routes.

### 3.8. Emailing the signed file — `c.Share` (`SIGN` permission)

Sends your signed PDF as an attachment to the next signer / recipient (`POST /share`). The CA does **not store** the file: it checks
that it has a valid eID signature, sends it, and discards it. A separate email goes to each recipient.

> Always on at the CA (no flag since 2026-10-16). Read the limits and quota from `c.ShareInfo(ctx)`;
> if `Enabled` is false, the email service is temporarily not configured (503).

```go
info, err := c.ShareInfo(ctx) // Enabled, MaxFileBytes, MaxRecipients, Quota{PerRPHour, PerRPDay, PerRecipientDay}, …
if err == nil && info.Enabled {
	res, err := c.Share(ctx, eid.ShareRequest{
		File:     signedPDF,                // ≤ 3 080 192 bytes, a PDF with a valid eID signature
		Filename: "contract.pdf",              // with a .pdf extension; "" = document.pdf
		To:       []string{"next@example.mn"}, // 1–5, no duplicates
		Subject:  "Contract — signature",      // ≤ 150; the CA adds a "‹RP name›: …" prefix
		Message:  "Please add the second signature", // ≤ 1000
		Lang:     "mn",                      // mn | en
	})
	var se *eid.ShareError
	switch {
	case errors.As(err, &se) && se.Code == eid.CodeMailFailed:
		// se.Recipients[i] == eid.ShareRecipientFailed — resend only to those
	case errors.As(err, &se) && se.Code == eid.CodeFileNotSigned:
		// se.Reason: eid.ShareReasonNoSignature | ShareReasonInvalid | ShareReasonUntrusted
	case err == nil:
		_ = res.DocID // if registered at the CA (a verify link goes in the email)
	}
}
```

| HTTP | `ShareError.Code` | Description |
|---|---|---|
| 400 | `REQUEST_INVALID`, `FILE_EMPTY`, `RECIPIENT_REQUIRED`, `TOO_MANY_RECIPIENTS`, `RECIPIENT_INVALID`, `RECIPIENT_DUPLICATE` | field errors |
| 413 | `FILE_TOO_LARGE` | the file / email exceeds the limit |
| 415 | `FILE_TYPE_NOT_SUPPORTED` | not a PDF (the extension, Content-Type and `%PDF-` must all match) |
| 422 | `FILE_NOT_SIGNED` | `.Reason`: `no_signature` \| `invalid` \| `untrusted` |
| 429 | `RATE_LIMITED` | quota; `.RetryAfter`, `.Retryable()` |
| 502 | `MAIL_FAILED` | `.Sent`, `.Failed`, `.Recipients` (`sent` \| `failed` in the order of `To`) |
| 503 | `MAIL_UNAVAILABLE`, `VALIDATOR_UNAVAILABLE`, `VALIDATOR_BUSY` (`SHARE_DISABLED` — older CA) | configuration / load (`VALIDATOR_*` — Retry-After) |

401 → `*eid.AuthenticationError`, 403 (no SIGN permission, IP/mTLS) → `*eid.ForbiddenError`. Quota: per RP 300 requests per hour / 3000 per day,
10 emails per day per recipient (take the actual values from `ShareInfo().Quota`). The timeout is `DefaultShareTimeout` (150 s);
if the ctx deadline is shorter, it wins.

### 3.9. "My QR" — in-person verification (`c.QR`, v0.21.0)

The citizen shows "My QR" in the eID app (`EIDMN-QR1:<token>`, 120 s, single-use). The RP (a till, POS, app) scans it and
calls `c.QR.Start` → on the citizen's phone one sentence ("You are about to share all the information in the "My information" section with <RP>")
+ PIN2 → the RP receives the citizen's whole "My information" (by source key, as it is) and the face image,
**signed with the citizen's QUALIFIED signature** (PS256 JWS, `x5c` = [SIGN certificate, issuing CA]). The RP needs only the `QR_PRESENT` permission.
The CA keeps no copy of the data — the presentation is read **only once** (again → 410).

```go
token, err := eid.ParseQR(scanned) // or c.QR.Parse; if it is not "EIDMN-QR1:<43>" → errors.Is(err, eid.ErrQRFormatInvalid)
sess, err := c.QR.Start(ctx, eid.QRStartRequest{
	QR:    scanned,
	Nonce: orderID, // optional: 16–128 printable ASCII; "" = 22 random characters
})
if errors.Is(err, eid.ErrQRTokenInvalid) { /* 404: expired / already used → ask for a new QR */ }

// sess can be stored (as JSON) — Result verifies sid and nonce. Polling UI: c.QR.Check(ctx, sess, 0).
p, err := c.QR.Result(ctx, sess, nil)
var sf *eid.SessionFailedError // USER_REFUSED, TIMEOUT …
var qe *eid.QRError
switch {
case errors.As(err, &sf):
case errors.Is(err, eid.ErrQRPending): // the wait ran out but the session is still active — call Result / Check again
case errors.Is(err, eid.ErrQRPresentationGone): // 410: already read → a new QR
case errors.As(err, &qe): // QR_CHAIN_INVALID, QR_SIGNATURE_INVALID … — DO NOT TRUST
}
for _, k := range p.Keys { fmt.Println(k, p.Data[k]) } // payload order
_ = p.Photo                     // JPEG bytes (or nil)
_ = p.Signer.ETSI               // = sub, the certificate's serialNumber (PNOMN-…)
_ = p.SHA256                    // = the CA's audit qrsha (to match in a dispute)
```

Verification (`eid.VerifyQRPresentation(ctx, jws, eid.QRExpect{…}, trust)` — the same across the three SDKs, using the CA's
`testdata/myqr_vectors.json`): compact JWS ≤ 512 KiB → the header is exactly `{alg: PS256, typ: eidmn-myqr+jwt, x5c: [2]}` →
chain leaf → (x5c[1] ∪ intermediates) → anchor (± 60 s; the leaf is not a CA, KU contentCommitment, QUALIFIED, RSA ≥ 2048, issuer
SKI allowlist) → revocation (`Trust.Revocation`; if nil, `NewOCSPChecker`, hard-fail by default) → RSASSA-PSS (SHA-256, salt
32) over the received bytes → claims (`iss`, `sub` = the cert serialNumber, `statement` = the sentence built from rp_name) → `aud` (case-insensitive)
→ `sid` → `nonce` → `0 < exp−iat ≤ 300`, `iat ≤ now+60`, `now < exp+60` → `data` (`source`
`^[a-z0-9_-]{1,32}$`, `fields` ≤ 128 entries (keys 1–64 characters, values ≤ 2048 bytes), `photo` strict base64 JPEG
≤ 150 KiB). Every error is a `*QRError{Code}` (`QR_JWS_MALFORMED`, `QR_HEADER_INVALID`, `QR_CHAIN_INVALID`, `QR_CERT_REVOKED`,
`QR_REVOCATION_UNKNOWN`, `QR_SIGNATURE_INVALID`, `QR_CLAIMS_INVALID`, `QR_AUDIENCE_MISMATCH`, `QR_SESSION_MISMATCH`,
`QR_NONCE_MISMATCH`, `QR_NOT_YET_VALID`, `QR_EXPIRED`, `QR_DATA_INVALID`) + an `ErrQR*` sentinel. Trust = `Config.Trust`:
if `TrustAnchorsPEM` is empty, the SDK's `NationalRootCAPEM` (`AllowUntrusted` does not apply here), and the issuer defaults to
`CitizenIssuingCASKI`.

The CA's other codes: 404 `QR_TOKEN_INVALID` / 410 `QR_PRESENTATION_GONE` → `*QRError` (`Cause` = `*APIError`); 400
`REQUEST_INVALID`, 403 `PERMISSION_DENIED` / `RP_REQUIRED` (`*ForbiddenError`), 409 `NO_SIGNING_CERTIFICATE`, 429
`RATE_LIMITED` (`*APIError`). `Config.QR.Issuer` — for test environments only.

### 3.10. Organizational electronic seal (e-Seal) — `c.Seal` (v0.24.0)

A **human-free, automated** system seals documents on behalf of an organization (invoices, certificates, statements): the key stays on eID's
server, no citizen/PIN/app is involved, and the response is immediate (no session). The RP needs that organization's **`SEAL:<orgEtsi>`** permission —
the permission is **granted by the organization itself** (below, "Seal permission, key, validity"); without it, `*ForbiddenError` 403.
For a citizen signing on behalf of an organization, see §3.4 (not a seal).

```go
sc, err := c.Seal.Certificate(ctx, "NTRMN-6235972")            // GET /seal/certificate/{orgEtsi} — the current issued seal cert
r, err := c.Seal.Seal(ctx, "NTRMN-6235972", digest, eid.SHA256) // POST /seal/{orgEtsi} — {digest, hashType}
// r.Signature — ECDSA (DER) over the digest, r.Certificate — the seal cert (DER), r.SealedAt
```

- `Seal` validates the response: the signature must match the digest under the response's certificate, and the certificate must be an e-Seal profile
  (`eid.IsSealCertificate`: KeyUsage = nonRepudiation only, no EKU purposes — extendedKeyUsage absent or empty) — otherwise `*ValidationError`. The chain and
  revocation are checked by `pades.SealPDF` (OCSP/CRL + self-validation).
- `hashType`: `eid.SHA256` (default) | `SHA384` | `SHA512`; if the digest length does not match, nothing goes over the network.
- **429 `RATE_LIMITED`** — `*APIError`; if `Retryable()` is true, retry after `RetryAfter` (300 seals per minute per RP).
  404 — organization not found; **409** — every code has its own sentinel (table below, v0.27.0).
- **503 `SEAL_SERVICE_DISABLED`** — see "Service switch" below (do not retry).
- `CertificateLevel` (`SealCertificate`, `SealResult`) comes **from the certificate itself** (`QSCD` if it has QcSSCD, otherwise
  `QUALIFIED`) — not from the CA's current key configuration.
- `Certificate` returns the organization's **current (issued, active)** certificate — it does not issue a new one; if not issued /
  revoked / outside the validity period, **409** (`ErrSealNotIssued` | `ErrSealCertRevoked` | `ErrSealCertExpired` |
  `ErrSealCertNotYetValid`) — an invalid certificate is never returned with 200. To seal a PDF: §7.3 `pades.SealPDF`.

#### Seal permission, key, validity (v0.27.0)

- **The permission (`SEAL:<orgEtsi>`) — with the organization's consent.** An eID operator creates a permission **request** for your RP; the permission arises only after that
  organization's **state-registry-verified ADMIN** sees the RP's name, domain, the organization's name and registry number in their eID app and
  approves with **PIN2**. Until approved (even if rejected or expired), sealing and
  certificate requests (`Seal`, `pades.SealPDF`, `RequestCertificate`, `CertificateRequest`) give `*ForbiddenError` 403
  (`Certificate` needs no permission). If an operator removes the permission or the organization is revoked, the permission becomes invalid (403). While the
  permission exists, the RP's name, callback host and mTLS certificate subject cannot be changed (an operator-side rule — to change them,
  the permission must be obtained again).
- **The key.** The seal key is ECDSA P-256, a **software key** held on eID's server (wrapped by an HSM key) —
  **not a QSCD**. The certificate level is `QUALIFIED` (under Mongolian law; without QcSSCD) — not EU qualified.
- **Validity, renewal.** The certificate is valid for 3 years. Renewal = a new request (`RequestCertificate`): a new key and a new
  certificate are issued, and the previous one is revoked (superseded). A document sealed with the previous certificate remains valid if it has a timestamp —
  the output of `pades.SealPDF` (PAdES-BASELINE-LT) satisfies this.
- **Revocation.** After revocation, `Seal` / `pades.SealPDF` / `Certificate` → `ErrSealCertRevoked`; a document sealed BEFORE the revocation
  is still valid in verification (`revoked_after_signing`).
- **Third-party verifiers.** The chain goes up to Mongolia's national Root CA; the OCSP / CRL addresses are in the certificate. Unless the national Root is
  trusted manually, Adobe and EU verifiers will not show the seal as trusted / qualified.

| HTTP `code` | `errors.Is` | Where | What to do |
|---|---|---|---|
| 409 `ORG_NOT_ACTIVE` | `eid.ErrOrgNotActive` | `Seal`, `SealPDF`, `RequestCertificate` | the organization is not ACTIVE — do not retry until restored |
| 409 `SEAL_NOT_ISSUED` | `eid.ErrSealNotIssued` | `Seal`, `SealPDF`, `Certificate` | no certificate issued — `RequestCertificate` |
| 409 `SEAL_CERT_REVOKED` | `eid.ErrSealCertRevoked` | `Seal`, `SealPDF`, `Certificate` | revoked — request a new certificate |
| 409 `SEAL_CERT_EXPIRED` | `eid.ErrSealCertExpired` | `Seal`, `SealPDF`, `Certificate` | expired — request a new certificate |
| 409 `SEAL_CERT_NOT_YET_VALID` | `eid.ErrSealCertNotYetValid` | `Seal`, `SealPDF`, `Certificate` | the validity period has not started |
| 409 `SEAL_KEY_UNAVAILABLE` | `eid.ErrSealKeyUnavailable` | `Seal`, `SealPDF` | the key is missing from the server configuration — contact eID support |
| 409 `SEAL_APPROVER_UNAVAILABLE` | `eid.ErrSealApproverUnavailable` | `RequestCertificate` | no ADMIN with an active eID |
| 404 `SEAL_REQUEST_NOT_FOUND` | `eid.ErrSealRequestNotFound` | `CertificateRequest`, `WaitForCertificate` | wrong request id |
| 503 `SEAL_SERVICE_DISABLED` | `eid.ErrSealServiceDisabled` | `Seal`, `SealPDF`, `RequestCertificate` | disabled by an operator — do not retry |

All are `*eid.APIError` (`Status`, `Code`, `Body` unchanged; `Retryable()` false); the code list is `eid.SealErrorCodes`.
`eid.ErrOrgNotActive` also matches the 403 `*ForbiddenError` (`ORG_NOT_ACTIVE`) of the OnBehalfOf flow.

```go
_, err := pades.SealPDF(ctx, c.Seal, org, pdf, pades.SealOptions{})
switch {
case errors.Is(err, eid.ErrSealNotIssued), errors.Is(err, eid.ErrSealCertRevoked), errors.Is(err, eid.ErrSealCertExpired):
	// no active seal certificate → c.Seal.RequestCertificate (the organization's ADMIN confirms with PIN2)
case errors.Is(err, eid.ErrOrgNotActive):
	// the organization is suspended / revoked — do not retry
}
```

#### Issuing a seal certificate (v0.25.0)

Neither the RP nor an operator issues the certificate directly — a **request** is created. Every valid **ADMIN** representative of the organization (with an active
eID device, ≤ 5) receives a request in the eID app and confirms with **PIN2**. As soon as one ADMIN confirms, the certificate is issued (`ISSUED`);
if they decline, `REJECTED`; if the approval period (the signing session TTL + 2 min) ends, `EXPIRED`.

```go
req, err := c.Seal.RequestCertificate(ctx, "NTRMN-6235972") // 202: req.RequestID, req.Status == eid.SealRequestPending
if errors.Is(err, eid.ErrSealApproverUnavailable) {
	// the organization has no ADMIN with an active eID
}
sc, err := c.Seal.WaitForCertificate(ctx, "NTRMN-6235972", req.RequestID, &eid.SealWaitOptions{Timeout: 10 * time.Minute})
var se *eid.SealRequestError
if errors.As(err, &se) {
	// se.Outcome: REJECTED | EXPIRED | FAILED → a new request; eid.SealRequestTimeout → you may wait again with the same RequestID
}
```

- `RequestCertificate` — `POST /seal/certificate/{orgEtsi}` → `*SealCertificateRequest` (`RequestID`, `Status`,
  `CreatedAt`, `ExpiresAt`, `Approvers`). If the organization has a PENDING request, the CA returns it (no new push).
- `CertificateRequest(ctx, org, requestID)` — `GET /seal/certificate/{orgEtsi}/requests/{requestId}`: `Status` = `PENDING` |
  `APPROVED` (being issued) | `ISSUED` (`Certificate` populated) | `REJECTED` | `EXPIRED` | `FAILED` (`Failure`:
  `SEAL_ISSUANCE_FAILED` | `PUSH_FAILED` | `SEAL_SERVICE_DISABLED`).
- `WaitForCertificate(ctx, org, requestID, *SealWaitOptions{Timeout = 15 min, Interval = 3 s})` — polls until ISSUED and returns a
  `*SealCertificate`; REJECTED / EXPIRED / FAILED / timeout → `*SealRequestError`. On 429/503 + Retry-After
  (`*APIError.Retryable()`) it waits out `RetryAfter` and continues; if `ctx` is cancelled, `ctx.Err()`.
- Errors: **409 `SEAL_APPROVER_UNAVAILABLE`** (`errors.Is(err, eid.ErrSealApproverUnavailable)`); **409 `ORG_NOT_ACTIVE`**
  (`eid.ErrOrgNotActive`, v0.27.0; previously a 409 without a code) — the organization is not ACTIVE; **404 `SEAL_REQUEST_NOT_FOUND`** (`eid.ErrSealRequestNotFound`; also for another organization's id); 403
  `*ForbiddenError` (no `SEAL:<orgEtsi>` permission); **429 `RATE_LIMITED`** + `RetryAfter` — 5 requests per hour per organization;
  **503 `SEAL_SERVICE_DISABLED`** (`eid.ErrSealServiceDisabled`) — issuance is disabled.

#### The RP requesting the seal permission itself — `RequestGrant` (v0.29.0)

Instead of an operator's request, the RP can request the organization's `SEAL:<orgEtsi>` permission **itself**. The person is identified not by ETSI —
but by **an authentication session started by your RP and completed with OK within the last 5 minutes**; that person must be the organization's
**CEO verified by the state registry**. The push goes only to them, and they approve with **PIN2** in their eID app. One
session → one request (calling again with the same session returns the same PENDING, with no new push). The SEAL permission is not required.

```go
// 1) log the CEO in anew through your RP (Auth.*); within 5 minutes after the session turns OK:
g, err := c.Seal.RequestGrant(ctx, "NTRMN-6235972", authSessionID) // 202: g.GrantID, g.Status == eid.SealGrantPending
switch {
case errors.Is(err, eid.ErrNotOrgCEO): // 403 — the person who logged in is not the CEO
case errors.Is(err, eid.ErrAuthSessionTooOld), errors.Is(err, eid.ErrAuthSessionAlreadyUsed): // 409 — log in again
case errors.Is(err, eid.ErrSealGrantAlreadyApproved): // 409 — the permission already exists
}
// 2) until the CEO approves with PIN2:
g, err = c.Seal.WaitForGrant(ctx, g.GrantID, &eid.SealWaitOptions{Timeout: 10 * time.Minute})
var ge *eid.SealGrantError
if errors.As(err, &ge) {
	// ge.Outcome: REJECTED | EXPIRED | FAILED | REVOKED (ge.Failure) → log in again and make a new request;
	// eid.SealGrantTimeout → you may wait again with the same GrantID
}
```

- `RequestGrant` — `POST /seal/grants {orgEtsi, sessionId}` → `*SealGrant` (`GrantID`, `OrgEtsi`, `Status`, `ExpiresAt`).
- `GrantStatus(ctx, grantID)` — `GET /seal/grants/{grantId}`: `PENDING` | `APPROVED` (`ApprovedAt`) | `REJECTED` | `EXPIRED`
  | `FAILED` | `REVOKED` (`RevokedAt`; `Failure` — `EXPIRED`, `PUSH_FAILED`, `RP_NOT_ACTIVE`, `ORG_NOT_ACTIVE`,
  `RP_CHANGED`, `RP_PERMISSIONS_FULL`, `CANCELLED`, `ORG_REVOKED`). Another RP's id → 404 `ErrSealGrantNotFound`.
- `WaitForGrant(ctx, grantID, *SealWaitOptions)` — polls until APPROVED (the same rules as `WaitForCertificate`: it follows 429/503 +
  Retry-After, other errors are returned immediately, and if `ctx` is cancelled, `ctx.Err()`).
- `c.Organization.SealGrants(ctx, personEtsi)` — `GET /organization/seal-grants/etsi/{personEtsi}` (`PKI_READ`; the citizen has
  logged in through your RP within the last 24 hours): every organization where the citizen is CEO (`OrgEtsi`, `OrgName`,
  `OrgStatus`) and their APPROVED / PENDING permissions (`RPName`, `RPDomain`, `Status`, `CreatedAt`, `DecidedAt`,
  `ExpiresAt`, `ApproverName`, `SealCount`, `SealCount30d`, `LastSealedAt`). `SealCount` / `SealCount30d` nil = statistics
  temporarily unavailable (not 0). The CA shows other RPs' permissions only in the eID portal — your RP sees only its own.
  Read-only — revocation is from the eID app.

| HTTP `code` | `errors.Is` | What to do |
|---|---|---|
| 400 `REQUEST_INVALID` | `eid.ErrRequestInvalid` | orgEtsi / sessionId is wrong |
| 403 `RP_NOT_REGISTERED` | `eid.ErrRPNotRegistered` (`*ForbiddenError`) | not a registered RP |
| 403 `NOT_ORG_CEO` | `eid.ErrNotOrgCEO` (`*ForbiddenError`) | the person who logged in is not the CEO |
| 404 `AUTH_SESSION_NOT_FOUND` | `eid.ErrAuthSessionNotFound` | the session does not exist / belongs to another RP |
| 404 `ORG_NOT_FOUND` | `eid.ErrOrgNotFound` | the organization is not registered |
| 409 `AUTH_SESSION_WRONG_FLOW` | `eid.ErrAuthSessionWrongFlow` | not an authentication session |
| 409 `AUTH_SESSION_NOT_COMPLETED` | `eid.ErrAuthSessionNotCompleted` | the login did not finish / failed |
| 409 `AUTH_SESSION_TOO_OLD` | `eid.ErrAuthSessionTooOld` | older than 5 minutes — log in again |
| 409 `AUTH_SESSION_ALREADY_USED` | `eid.ErrAuthSessionAlreadyUsed` | log in again |
| 409 `ORG_NOT_ACTIVE` | `eid.ErrOrgNotActive` | the organization is not ACTIVE |
| 409 `RP_NOT_ACTIVE` | `eid.ErrRPNotActive` | the RP is inactive |
| 409 `SEAL_GRANT_ALREADY_APPROVED` | `eid.ErrSealGrantAlreadyApproved` | the permission already exists |
| 409 `RP_PERMISSIONS_FULL` | `eid.ErrRPPermissionsFull` | contact the eID operator |
| 409 `SEAL_APPROVER_UNAVAILABLE` | `eid.ErrSealApproverUnavailable` | the CEO has no active eID device |
| 404 `SEAL_GRANT_NOT_FOUND` | `eid.ErrSealGrantNotFound` | (`GrantStatus`) the id is wrong / belongs to another RP |
| 429 `RATE_LIMITED` | `*APIError.Retryable()` | after `RetryAfter` |

The code list is `eid.SealGrantErrorCodes`.

#### Service switch — `SEAL_SERVICE_DISABLED`

An eID operator can disable **seal certificate issuance** and **sealing** separately, platform-wide. When disabled,
`RequestCertificate` (`service: "issuance"`) and `Seal` / `pades.SealPDF` (`service: "sealing"`) receive
`503 {"error", "code": "SEAL_SERVICE_DISABLED", "service"}` — without `Retry-After`.

```go
r, err := c.Seal.Seal(ctx, org, digest, eid.SHA256)
if errors.Is(err, eid.ErrSealServiceDisabled) {
	var ae *eid.APIError
	if errors.As(err, &ae) {
		// ae.Status == 503, ae.Service == eid.SealServiceSealing | eid.SealServiceIssuance, ae.Retryable() == false
	}
	// do not retry automatically — show the user "the service is temporarily disabled" and leave it in the queue
}
```

- `*APIError.Retryable()` is **always false** for this code (even if a proxy adds `Retry-After`) — the SDK (`WaitForCertificate`,
  `pades.SealPDF`) does not retry and returns the error as is; since the CA does not say when it will be back on, the RP should not make short retry loops either.
- If a pending request was approved by an ADMIN but issuance is disabled, the request becomes `FAILED` with `Failure` =
  `SEAL_SERVICE_DISABLED` and no certificate is issued: `WaitForCertificate` → `*SealRequestError`, and
  `errors.Is(err, eid.ErrSealServiceDisabled)` is true. Once it is back on, make a new `RequestCertificate`.
- Never disabled: `Certificate`, `CertificateRequest` (status polls), verification (`/validate/*`, `pades.ValidatePDF`),
  OCSP/CRL, revocation — documents sealed earlier stay valid.
- The current status is in the `seal` block of `/.well-known/eid`: `{"issuanceEnabled", "sealingEnabled", "disabledCode"}`.

## 4. Security — why the `Validator` is required

**Do not trust `EndResult == "OK"` on its own** — if the RP-API is corrupted/proxied, a forged OK could arrive.
The `Validator` (<https://developer.eidmongolia.mn/#verification>):

1. `State == COMPLETE` (otherwise `*ValidationError` — e.g. a RUNNING from `WaitForResult`) and `EndResult == OK` (otherwise
   `*SessionFailedError`).
2. Verifies the citizen's certificate by chain up to the **trust anchor (Mongolian National Root CA, `eid.NationalRootCAPEM`)**
   (Root 01 → National Issuing CA 02 → Gerege Issuing CA 03 → eID Mongolia Issuing CA 04 → citizen) — Go's
   `x509.Certificate.Verify` (RFC 5280): CA basicConstraints + **pathLenConstraint** (04 is `pathlen:0`), the CA's
   keyUsage keyCertSign, **name constraints**, **EKU** (auth → clientAuth, sign → emailProtection — the CA's profile;
   if an intermediate CA has an EKU, it must fall within it), an unrecognized **critical extension** → rejected, the signature, and the validity period (the chain is checked at
   the leaf's validity period, within `ClockSkew`). If no trust anchor is configured, **fail-closed**
   (`AllowUntrusted` is for dev/test only). The OS trust store is not trusted. The response does not carry the chain — if `IntermediatesPEM` is nil,
   the SDK's built-in 02, 03, 04 (`eid.CitizenIntermediatesPEM`, since v0.6.0). certificatePolicies in the chain are
   not checked (the CA's chain has no policyConstraints; the level is — 3).
3. The certificate is within its validity period (`ClockSkew`) + the required level (`RequiredLevel`, default `QUALIFIED`; `QSCD` satisfies it).
   **Since v0.6.0 the level is determined from the certificate** (`eid.CertificateLevelOf`): for a signing certificate, qcStatements
   QcCompliance → QUALIFIED (+ QcSSCD → QSCD; phone and USB tokens issued after 2026-11-06 are QUALIFIED), without qcStatements
   (tokens issued before that) → ADVANCED; for an authentication certificate the CA does not write qcStatements, so by profile → QUALIFIED:
   KeyUsage keyEncipherment (the phone's P-CITIZEN-AUTH), or EKU clientAuth + emailProtection with the national policy
   `2.16.496.1.101.1.2.8` (the token's P-CITIZEN-AUTH-TOKEN, since v0.22.2); anything else → ADVANCED. If the response's `CertificateLevel`
   is higher than that, it is rejected; if lower, the response's is taken (the CA declares an old token's AUTH as ADVANCED).
   The `CertificateLevel` of `VerifiedIdentity` / `VerifiedSignature` / `Signer` = this value.
4. The signature (`rsassa-pss` / `shaNNNWithRSAEncryption` / `ecdsa-with-SHA256`):
   - **auth** → the ACSP_V2 payload (`smart-id|ACSP_V2|serverRandom|rpChallenge|userChallenge|B64(rpName)|B64(brokeredRpName)|B64(SHA-256(interactions))|interactionTypeUsed|initialCallbackUrl|flowType`),
     hash = the request's `HashAlgorithm`; `flowType` must be in the offered flows, EXACTLY matching if `ExpectedFlowType` is given,
     `UserChallengeVerifier` is required for Web2App/App2App; `initialCallbackUrl` may only be `""` or your callback.
   - **sign** → over your digest (prehashed); if `ValidateSignOptions.ExpectedFlowType` is given, the response's `flowType` must EXACTLY match
     (it is not part of the signature — a response check).
   - The algorithm ↔ key type is checked (an RSA name only with an RSA certificate); the hash must EXACTLY match the requested one (downgrade
     protection). ECDSA is allowed only for an `ecdsa-with-SHA256` + EC P-256 + SHA-256 session (the CA's ECDSA credential signs nothing
     but SHA-256; if an ECDSA response arrives for a SHA-384/512 session, `ValidationError`).
5. Revocation — `TrustConfig.Revocation` (an OCSP/CRL hook, `RevocationHardFail` by default) → `CheckRevocation`, or
   `CheckRevocationStatus` (`good` / `unchecked` (soft-fail) / `skipped` (no hook) + an error). For QUALIFIED
   non-repudiation the RP configures it. The ready-made hook: `eid.NewOCSPChecker(eid.OCSPOptions{})` — the certificate's AIA OCSP
   (revoked/unknown → revoked; no response → unknown, the mode decides). For a one-off with a different checker/mode: `CheckRevocationWith`.
   `OCSPOptions` (v0.5.2+): `CacheTTL` (the cache of good = min(CacheTTL, NextUpdate−now); default 5 min, negative = no cache);
   `Observe func(eid.OCSPObservation)` — on every check (even from the cache) `Status`, the `Responder` URL, `Duration`, `Cached`, `Err`
   (no PII) — for metrics/audit. With no response the checker returns `RevocationUnknown` + `*eid.OCSPError` (`Kind`: `no_responder`,
   `no_issuer`, `timeout`, `network`, `http_status` (+`HTTPStatus`), `responder_status`, `parse`, `signature`, `invalid`;
   `errors.Is(err, eid.ErrOCSPNoAnswer)`); `CheckRevocationWith` resolves this unknown by the mode — soft →
   `unchecked`, nil (the reason is in `Observe`); hard → `*ValidationError` (`Cause` = `*OCSPError`). An `id-kp-OCSPSigning` responder
   issued by the issuer and embedded in the response (RFC 6960 §4.2.2.2, ocsp.eidmongolia.mn's "eID OCSP Responder") is
   accepted (tested with a real response: `testdata/ocsp-eid-delegated.der`); a response signed by the issuer itself with its own certificate
   embedded is also accepted (since v0.6.0; RFC 6960 §4.2.2.2), verified with the issuer's key.
6. **Issuer and purpose (defaults since v0.6.0):** if `AllowedIssuerSKIs` is empty, `[]string{eid.CitizenIssuingCASKI}`
   (when TrustAnchorsPEM is configured) — only certificates from the citizen Issuing CA (04) (an organization's
   05 etc. under the same root are blocked; to disable: `AllowAnyIssuer: true`); the purpose is checked by default — auth → KU digitalSignature +
   EKU clientAuth, sign → KU nonRepudiation (the CA's profile): a signature by an authentication (PIN1) key does not qualify for `ValidateSign`
   (to disable: `SkipKeyUsageCheck: true`, not recommended; `CheckKeyUsage` is deprecated and has no effect). `SchemeName` —
   the CA's `acsp_scheme_name` (default `smart-id`).

If any step fails, `*eid.ValidationError` — **do not trust** the response. The error text never contains the citizen's name, PNOMN or registry number
(certificates by serial, paths as `/etsi/…`) — it can be written straight to logs.

## 5. Error types (`errors.As`)

| Error | Meaning |
|---|---|
| `*eid.AuthenticationError` | 401 — API secret wrong/missing; for a CA JSON response `.Code`/`.Message`, empty for a proxy's (`.Body`, `.Header`) |
| `*eid.ForbiddenError` | 403 — IP allowlist / mTLS / the RP's permission; if `OnBehalfOf` is rejected, `.Code` |
| `eid.ErrNoSigningCertificate` / `ErrCertChoiceInvalid` / `ErrRequestInvalid` | `errors.Is` — the `Code` of `*eid.APIError` (409 `NO_SIGNING_CERTIFICATE`, 409 `CERT_CHOICE_INVALID`, 400 `REQUEST_INVALID`) |
| `*eid.ShareError` | `Share`'s 4xx/5xx (other than 401/403) — `.Code`, `.Reason` (422), `.Sent`/`.Failed`/`.Recipients` (502); `Unwrap` → `*eid.APIError` |
| `*eid.APIError` | other HTTP errors (`.Status`, `.Body`, `.Code`, `.RetryAfter`, `.Header`, `.Retryable()` — e.g. 404 `ORG_NOT_FOUND`) |
| `*eid.ResponseTooLargeError` | the response exceeds the SDK's limit (JSON 4 MiB) — `.Op`, `.Limit` |
| `*eid.NetworkError` | network / timeout (`.Timeout`, `Unwrap` → `context.DeadlineExceeded` etc.); the citizen's number becomes `…` in `.Op` |
| `*eid.SessionFailedError` | endResult ≠ OK (`TIMEOUT`, `USER_REFUSED…`) — `.EndResult` |
| `*eid.ValidationError` | the chain / signature / level / flow check failed |
| `*eid.DeviceLinkError` | a device link cannot be built (the shape of the input) |

## 6. mTLS

```go
cert, err := tls.LoadX509KeyPair("rp.crt", "rp.key")
c, err := eid.NewClient(eid.Config{
	/* … */
	HTTPClient: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}},
})
```

## 7. Client-side PAdES (`pades`)

The PDF **does not go to any eID server** (the Smart-ID + DigiDoc model): the CA only signs a 32-byte hash (the DTBS), and all the
work on the PDF (the verification QR page, placeholder, signedAttrs, CMS, RFC 3161, OCSP/CRL, DSS, its own validation) is done by this
library. The profile `pades-client/1` derives from the CA's server-side writer (the verify page is a new minimal writer,
without runtime compression); the same input → the same bytes.

```go
import "github.com/gerege-systems/eid-mongolia-sdk-go/pades"

// 1. The certificate (certificate-choice) — needed BEFORE hashing, for signingCertificateV2 in signedAttrs.
cc, err := c.Sign.CertificateChoiceByEtsi(ctx, "PNOMN-12345678", nil)
r, err := c.Session.WaitForResult(ctx, cc.SessionID, nil)
signer, err := c.Validator.ValidateCertificateChoice(r, cc.SessionID)
// 2. (when signing on behalf of an organization) the claimed role computed by the CA — pass it through unchanged.
reps, err := c.Organization.GetRepresentations(ctx, "PNOMN-12345678")
claimedRole := reps.Representations[0].ClaimedRole // the row whose OrgEtsi == onBehalfOf
// 3. Prepare — the PDF stays on your server; a QR page for the first eID signature (mn, Lang: "en").
p, err := pades.Prepare(pdfBytes, pades.PrepareOptions{SignerCert: signer.Certificate.Raw, VerifyPage: true,
	FileName: "Contract No. 12.pdf", ClaimedRole: claimedRole, Reason: "On behalf of Test LLC"})
// 4. Have the DTBS signed by EXACTLY THAT device. The default algorithm of DigestForSigner / DeviceLinkForSigner =
//    sha256WithRSAEncryption (PKCS#1 v1.5) — required for the CMS (Complete rejects DigestByEtsi's default rsassa-pss
//    with REQUEST_INVALID).
s, err := c.Sign.DigestForSigner(ctx, signer, base64.StdEncoding.EncodeToString(p.DTBS), interactions,
	&eid.SignOptions{OnBehalfOf: "NTRMN-6235972"})
res, err := c.Session.WaitForResult(ctx, s.SessionID, nil)
_, err = c.Validator.ValidateSign(res, s.Sign.Digest, s.Sign.HashAlgorithm, eid.ValidateSignOptions{
	ExpectedAlgorithm: s.Sign.SignatureAlgorithm, ExpectedCertificate: signer.Certificate, ExpectedFlowType: eid.FlowNotification})
sig, _ := base64.StdEncoding.DecodeString(res.SignatureValueB64)
// 5. Complete — TSA https://tsa.timeserver.mn/, OCSP/CRL (AIA/CDP), DSS, its own validation.
done, err := pades.Complete(ctx, p.State, sig, pades.CompleteOptions{})
// if OCSP/CRL fails transiently the SDK retries itself twice (~1 s, ~3 s + jitter; no new PIN) — CompleteOptions.LTVRetries.
if pades.ErrorCode(err) == pades.CodeTSAUnavailable { /* p.State is unchanged — try again */ }
// 6. Registration at the CA (docID, /verify) — required. If Medium is "", it is derived from SessionID (phone ⇔ sessionID); for a signature with a ClaimedRole
// signature without OnBehalfOf gives REQUEST_INVALID (before it reaches the CA).
reg, err := pades.Registration(done, pades.RegistrationOptions{Medium: eid.PDFMediumPhone, SessionID: s.SessionID,
	OnBehalfOf: "NTRMN-6235972"})
_, err = c.PDF.RegisterSignature(ctx, reg) // POST /pdf/signatures
// done.PDF — PAdES-BASELINE-LT
rep, err := pades.ValidatePDF(ctx, done.PDF, pades.ValidateOptions{}) // the same report as the CA's /v3/validate/pdf (§7.2)
```

The full version, checked by the compiler: `pades/example_test.go` (`Example`).

- `signature`: RSA PKCS#1 v1.5, ECDSA `r‖s` (P-256 64 / P-384 96 bytes) or DER — automatically by the certificate's key;
  RSASSA-PSS → `SIGNATURE_INVALID` ("PKCS#1 v1.5 required"; the same code as TS / .NET / Swift / Kotlin).
- `RegisterSignature` — `POST /pdf/signatures`, the body is exactly the CA's `PDFSignatureRegisterRequest` (`hasPage` is not
  sent; `signerEtsi` = the certificate's SERIALNUMBER). For the first signature to be registered it must have a verify page.
  `Created` — `true` is 201 (new), `false` is 200 (a repeat of the same body). If the previous signature was assembled by the CA (mode A), via `Registration`'s
  `PriorSignatures` (the pair CMS + `sha256(doc[0 : ByteRange[2]+ByteRange[3]])`), after a 409
  `PRIOR_MISMATCH` the SDK reconciles by revision itself (it does not try if you set `PriorRevisionSHA256` by hand).
- The trust anchor is the embedded Mongolian National Root CA (01); 02–05 is the embedded intermediate chain (if `Chain` is not given, it is built
  from the signer's issuer). For a test PKI, `CompleteOptions.Roots` / `VerifyOptions.Roots` (DER).
- Errors are `*pades.Error` (`Code`): `PDF_INVALID`, `PDF_ENCRYPTED`, `PDF_LOCKED` (DocMDP P=1), `PDF_TOO_LARGE`
  (input > 10 223 616 bytes), `PDF_TOO_MANY_SIGNATURES`, `PDF_PRIOR_SIGNATURE_INVALID`, `PDF_FOREIGN_SIGNATURE` (a previous
  signature's signer is not from eID's 04/05 or its SubFilter is not CAdES — [PRECHECKS.md](pades/PRECHECKS.md)), `SIGNER_INVALID`, `REQUEST_INVALID`, `SIGNATURE_INVALID`, `TSA_UNAVAILABLE`,
  `LTV_UNAVAILABLE`, `SELF_VALIDATION_FAILED`, `PLACEHOLDER_OVERFLOW`, `STATE_INVALID`.
- **LTV retry (v0.6.0)** — if gathering the OCSP/CRL (DSS) fails (the `LTV_UNAVAILABLE` condition, e.g. the national CRL mirror temporarily returns 404),
  `Complete` retries itself with the same state, signature and TSA timestamp: `CompleteOptions.LTVRetries` (`*int`; nil =
  `pades.DefaultLTVRetries` 2 — 3 attempts in total, waits of ~1 s, ~3 s + 0–25% jitter; `0` — disable; outside 0–10 →
  `REQUEST_INVALID`). If all fail, `LTV_UNAVAILABLE`; if `ctx` is cancelled, the wait is aborted and an `LTV_UNAVAILABLE` wrapping `context.Canceled` is returned.
  The same as the TS SDK 0.18.3's `ltvRetries` — both TS and Go have LTV retry.
- **LTV revocation ordering (v0.28.1)** — `Complete` by the certificate's role:
  - the first (end-entity: citizen, TSA) certificate in the chain — **OCSP first** (10 s timeout, `thisUpdate > genTime`), the CRL is
    also fetched and both go into the DSS; if there is no valid OCSP response, the CRL;
  - CA certificates (the rest of the chain) — **CRL first**; if a valid CRL is obtained, that certificate's OCSP responder is NEVER contacted
    (only the CRL in the DSS); only if there is no valid CRL, OCSP (10 s timeout).

  The fetches for each certificate are concurrent; the DSS is in chain order. The acceptance rules, "revoked" = a hard error, and fail-closed
  are unchanged. `ValidatePDF` (online checks only for certificates issued by 04/05) is unchanged.
- Re-signing a signed document adds no page; the docID is read from the first page's `/verify/<uuid>` link.
- `VerifyPagePosition: pades.VerifyPageFirst` (v0.15.0+) — the page goes at the START of the document (page 1); the default
  `pades.VerifyPageLast` (at the end, byte-identical to before). `Appearance.Page`, `SuggestPlacement` and `Placement.Page` are both
  counted by the input PDF's pages (the added page is not counted). PAGE_SPEC §8a, PLACEMENT_SPEC §1b.

### 7.1. Visible signature (optional)

The default is invisible (byte-identical to before). If the RP gives a rectangle on the page, the widget draws an appearance with the name, (for onBehalfOf) the role,
"eID Mongolia-аар зурсан" / "Signed with eID Mongolia", the date `YYYY-MM-DD HH:MM (+08)`, and a QR for each signature
(`https://ca.eidmongolia.mn/verify/<docID>/<revIndex>`):

```go
p, err := pades.Prepare(pdfBytes, pades.PrepareOptions{SignerCert: cert, VerifyPage: true, FileName: "Contract.pdf",
	Appearance: &pades.Appearance{Page: 0, X: 36, Y: 36, Width: 220, Height: 64}}) // Page 0 = the last page, NOT the input's eID verify page
```

- Coordinates — pt, from the **screen-visible** (after `/Rotate`) bottom-left corner of the page's CropBox (or MediaBox if absent);
  `/Rotate` 0/90/180/270 are all supported (the appearance is drawn upright). Rounded to 0.01 pt.
- `Page` is the page of the document given to Prepare (from 1; an explicit number skips nothing). 0 = the last page, NOT the eID verify page —
  the verify pages added by this Prepare and by earlier revisions are not counted (v0.12.0+, PLACEMENT_SPEC §1a).
- `X, Y` is the requested position: if the page's content (text, table rules, images, a previous signature) is in that spot,
  the appearance moves to free space — first the mirrored column (bottom-right → bottom-left), then up in 12 pt steps.
  The result: `Prepared.Placement` (`Status`: `requested` | `moved` | `overlap` — no free space, at the requested position
  | `unscanned` — the page could not be read within the limit). Details: [PLACEMENT_SPEC.md](pades/PLACEMENT_SPEC.md).
- `Exact: true` (v0.14.0+) — a position chosen by the citizen: it never moves, and is drawn exactly at `Page/X/Y/Width/Height`
  (going off the page gives `REQUEST_INVALID`); if it overlaps content, `Status` = `overlap`. PLACEMENT_SPEC §6a.
- `pades.SuggestPlacement(pdf, appearance)` (v0.14.0+) — the position Prepare would choose, without a signature, certificate or the network
  (`Page` resolved, `X/Y/Width/Height/Status`) plus `PageWidth/PageHeight`, `PageCount`, `Pages[]` (the visible size of
  each page, in pt) — show the default position in the UI, and after the user moves it, pass it to Prepare with `Exact: true`.
  Coordinates: from the visible bottom-left corner (the UI's top-left `top` → `y = PageHeight − top − Height`). PLACEMENT_SPEC §6b.
- Height ≥ 45 pt (QR module ≥ 1 pt), text not fitting (the name shrinks down to 7 pt, the rest to 5 pt), going off the page, no page,
  a name that cannot be written as `/Name`, or an unknown docID → `REQUEST_INVALID`. The date is the declared SigningTime (the TSA's time is not
  known at prepare).
- The `Verify` report: `visible` (this signature is visible), `visible_later_signature`. The verifier accepts only exactly this form (it regenerates the widget +
  `/AP` and compares at the byte level). Details: [APPEARANCE_SPEC.md](pades/APPEARANCE_SPEC.md).

### 7.2. Verifying a signed PDF — `pades.ValidatePDF` (v0.7.0)

The RP verifies on its own backend (without sending the file anywhere) with the code of the CA's public verifier (`/v3/validate/pdf`) —
the report is identical to the CA's JSON (snake_case). The same rules in the browser: the TS SDK's `validatePdf` (`@gerege-systems/eid-mongolia-sdk/validate`).

```go
rep, err := pades.ValidatePDF(ctx, pdfBytes, pades.ValidateOptions{}) // default: the embedded national Root CA, online revocation
switch pades.ErrorCode(err) {
case pades.CodePDFNoSignature, pades.CodePDFInvalid, pades.CodePDFTooLarge, pades.CodePDFTooManySignatures: // 4xx
case pades.CodePDFEncrypted: // v0.7.1: encrypted (/Encrypt) — tell the user to remove the protection and resubmit
case pades.CodeRequestInvalid: // ValidateOptions.Roots/Intermediates/Issuers cannot be parsed
}
if rep.Indication == pades.Valid { /* all signatures are valid */ }
for _, s := range rep.Signatures {
	_ = s.SignerName           // from the certificate (claimed_name — written in the PDF, unverified)
	_ = s.SigningTime          // the trusted RFC 3161 time
	_ = s.SignatureLevel       // PAdES-BASELINE-B | -T | -LT
	_ = s.CertificateLevel     // QUALIFIED | QSCD | ADVANCED (qcStatements)
	_ = s.Problems             // integrity_failed, untrusted_chain, revoked, modified_after_signing …
}
```

- Checks: ByteRange (the gap is exactly this `/Contents`) and messageDigest, the CMS signature, signingCertificateV2, the chain
  (national 01 → 02/03 → 04/05), KU/EKU (citizen SIGN, organization seal, doc-signer; AUTH/TLS → `wrong_key_usage`),
  validity (at the timestamp's time), the RFC 3161 token (TSA chain, critical timeStamping EKU), every revision AFTER the signature only in a form
  permitted for eID's signature/LTV (anything else → `modified_after_signing`), the visible signature (APPEARANCE_SPEC
  §5), and LTV completeness (`ltv`).
- Revocation (for certificates issued by eID's 04/05): online — the AIA OCSP, otherwise the CDP CRL (signed by the issuer); with no response
  or with `Offline: true`, the document's DSS. If neither → `revocation_unavailable` (indeterminate). Revoked after the
  timestamp → `revoked_after_signing` (still valid). Only the certificate's serial (OCSP) goes over the network, not the document.
- Revocation evidence rules (v0.7.2): the OCSP is for THIS certificate (CertID = hash of the chain issuer's name/key +
  serial), and the CRL is the issuer's (name, AKI, signature). A "good" must be fresh at the time of checking: thisUpdate not in the future
  (5 min tolerance), nextUpdate not passed, and either thisUpdate ≤ 24 hours ago or thisUpdate…nextUpdate covers the check time
  (check time = the trusted timestamp's time, otherwise `Time`/now). Otherwise it is not counted → `revocation_unavailable`.
  An issuer-signed "revoked" evidence (OCSP or CRL, online or DSS) always overrides a "good".
- **Untrusted PDF.** `Prepare`/`ValidatePDF`/`Verify`/`Complete` check array/dictionary nesting before parsing
  (`> 256` → `PDF_INVALID` in `Prepare`/`ValidatePDF`/`Verify`, `STATE_INVALID` in `Complete`; in both,
  `errors.Is(err, pades.ErrPDFStructure)`) (v0.7.2; previously a ~2 MB `[[[…` document
  would bring the whole process down with a `fatal error: stack overflow`). This is only one layer of defence — treat an externally supplied
  PDF as untrusted input: limit the size (≤ 10 MiB), set a timeout on every request, and if possible parse it in a separate
  process/container (with CPU/memory limits).
- `key_medium`: from the certificate only in the SDK — a citizen SIGN with qcStatements → `phone`, otherwise `unknown`. The CA (`POST
  /v3/validate/pdf`) determines `token` from its own registry, and `server_software` / `server_hsm` for organizational seals issued by eID
  (the key is on the server side; this is not a claim of QSCD) — the values are `pades.KeyMediumToken` | `KeyMediumPhone` |
  `KeyMediumServerSoftware` | `KeyMediumServerHSM` | `KeyMediumUnknown` (v0.27.0). `session_id`, `doc_id`, `on_behalf_of_*`, `stamp_lookup` come from the CA's registry — they are not in the SDK.
- An encrypted PDF (`/Encrypt` — RC4, AES-128, AES-256, even with an empty user password) → `PDF_ENCRYPTED` (v0.7.1;
  previously `PDF_INVALID`, and with RC4 a correct signature was wrongly treated as invalid as `malformed_signature`). The same in the TS SDK and the CA.
- `Verify` (v0.5) = `ValidatePDF` + `Offline: true` (deprecated; for a document with no signatures it returns an empty `valid` as before).
- Conformance: `pades/testdata/validate/` — Go, TS and the CA produce the same report from the same suite.

Go is the **reference implementation** (with the full verifier `Verify`, for the backend); the native TS / Swift / Kotlin / C# SDKs follow the signing
path ([PROFILE.md](pades/PROFILE.md), [PAGE_SPEC.md](pades/PAGE_SPEC.md), [PRECHECKS.md](pades/PRECHECKS.md),
[WIRE.md](pades/WIRE.md), [APPEARANCE_SPEC.md](pades/APPEARANCE_SPEC.md), [PLACEMENT_SPEC.md](pades/PLACEMENT_SPEC.md)) 1:1 and produce byte-identical goldens. There is no compression at runtime (xref/DSS/pages) — for
byte-identity across languages.

The golden vectors: `pades/testdata/golden/` (README, tag `pades-golden-v6`) — checked by every native SDK's CI; this repository's CI
independently checks every output with qpdf (`--check`) and pyHanko (INTACT/VALID/TRUSTED, LT from the DSS, whether it is visible).

### 7.3. Sealing a PDF with an organizational seal — `pades.SealPDF` (v0.24.0)

```go
done, err := pades.SealPDF(ctx, c.Seal, "NTRMN-6235972", pdfBytes, pades.SealOptions{Reason: "Invoice"})
// done.PDF — PAdES-BASELINE-LT, with the organization's seal
```

The flow: the seal certificate → `Prepare` (SignerCert = the seal cert) → the 32-byte DTBS is sealed via `POST /seal/{orgEtsi}` (SHA-256)
→ `Complete`. The PDF does not go to eID. **An RFC 3161 timestamp is required** (the eID TSA, `SealOptions.Complete.TSAURL`):
if the TSA is unreachable, `TSA_UNAVAILABLE`, and a file without a seal/timestamp is never returned; OCSP/CRL + DSS → B-LT, then
self-validation. There is no verification (QR) page — a seal does not enter the citizen signature registry (`POST /pdf/signatures`),
so no `/verify/{docID}` link is provided.

**The visible stamp (default, Unreleased).** The seal leaves an organization seal stamp on the document's last (not the eID verify) page:
the organization's name, "eID Mongolia-аар тамгалсан" / "Sealed with eID Mongolia", and the sealing time — no QR, link or role
(`pades/APPEARANCE_SPEC.md` §6). Placement: 220 × 64 pt, the bottom-right corner (36 pt margin; fitted on a small page);
if there is content there, it moves to free space under PLACEMENT_SPEC's rules, and if there is no free space, it stays in the bottom-right corner over the content
(`overlap`). If the stamp does not fit on the page (e.g. a very small page), the seal is invisible and `done.Placement` = nil.
`SealOptions.Appearance` — to set the position yourself (the same as the citizen `Appearance`, `Exact` too), `SealOptions.Invisible: true` —
the previous invisible output (byte-identical). The result is in `done.Placement`. Earlier signatures (including a citizen's visible signature)
remain valid. **Note:** verifiers older than this release (the CA's `/v3/validate/pdf`, the TS SDK) do not recognize the seal stamp,
so they report an earlier signature as modified — use `Invisible: true` until they are updated.

**A seal stamp with a QR (Unreleased — verifier only).** `pades/APPEARANCE_SPEC.md` §6.5: the same structure as the citizen stamp
(QR + `/verify/<docId>/<rev>`), with the seal's label and no role line — it makes a document sealed without a verify page (an invoice,
a certificate) scannable and verifiable. **This release teaches only the verifiers (`pades.ValidatePDF`, `Complete`'s
self-validation) the QR seal; the writer (`SealPDF`) still emits the QR-less stamp** (byte-identical to v0.30.0), there is no public
option for the QR — it comes in a following release together with seal registration. Do not emit a seal with a QR until the CA and TS verifiers ship §6.5.
A stamp without a QR stays valid forever. Also `Prepare`'s docId (§6.6): if a document without a verify page has a QR (marker) **seal** stamp,
it takes its docId — for both visible and **invisible** signatures (previously an invisible one took `opts.docId` or empty),
and giving a different `opts.docId` is `REQUEST_INVALID`. A random docId is not generated for a signed document: after a QR-less
seal, when a citizen makes a visible signature `opts.docId` (which the caller registers itself) is required, otherwise `REQUEST_INVALID`
as before.

The verifier (`pades.ValidatePDF`, the CA's
`/v3/validate/pdf`) classifies this signature as `certificate.usage = "seal"` — show it to users as an "Organization seal".
Errors: `CodeSignerInvalid` (the cert is not an e-Seal, or it changed between sealing — try again),
`CodeSignatureInvalid`, `CodeTSAUnavailable`/`CodeLTVUnavailable` (transient), and the RP-API errors (`*ForbiddenError`, `*APIError`)
remain — if sealing is disabled, 503 `eid.ErrSealServiceDisabled` (§3.10; `SealPDF` does not retry and never returns an unsealed file). The `pades.Sealer` interface (satisfied by `*eid.SealService`) — can be substituted in tests.

## Development

```bash
go vet ./... && go test -race ./...
go test ./pades -run Golden -update                                              # rewrite the golden files (only when the profile changes)
```

Tests: the CA server's device link golden vectors (`testdata/devicelink_golden.json`, the same file as the TS SDK's), the Smart-ID
ACSP_V2 vector, the RFC 7636 PKCE vector, real public CA certificates.

### Contract check

Every RP-API route the SDK calls (`routes.go`) must be in the live [`/.well-known/eid`](https://rp.eidmongolia.mn/.well-known/eid)'s
`endpoints`. Routes that are in discovery but not covered by the SDK are a WARN (not a failure). Because it needs the network, it is not part of a plain `go test`:

```bash
go test -count=1 -v -tags contract -run Contract ./...
```

CI: `.github/workflows/contract.yml` — PRs, `main` pushes, daily at 00:00 UTC, manual.

License: MIT.
