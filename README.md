# eid-mongolia-sdk-go

**eID Mongolia** relying-party SDK for Go — иргэнийг утсаар нь нэвтрүүлэх (authentication) ба хууль ёсны цахим гарын
үсэг (qualified signature) зуруулах, «eID-ээр нэвтрэх» (OpenID Connect). RP-API v3, Smart-ID нийцтэй.
TypeScript хувилбартай ([gerege-systems/eid-mongolia-sdk](https://github.com/gerege-systems/eid-mongolia-sdk))
функциональ ижил. Бүрэн баримт: <https://developer.eidmongolia.mn/#overview>.

> SDK **backend**-д ажиллана: бүх дуудлага API secret (`rp_sk_…`)-ээр баталгаажна. Secret, `SessionSecret`-ийг
> браузер/гар утсанд хэзээ ч бүү гарга — браузерт зөвхөн таны backend-ийн өгсөн холбоос / QR / товч харагдана.

- Go ≥ 1.22, **зөвхөн стандарт сан** (гадны хамааралгүй).
- Багц: `eid` (RP-API, device link, validator, PDF) ба `eid/oidc` («eID-ээр нэвтрэх»).

[English summary](#english)

## Суулгах

```bash
go get github.com/gerege-systems/eid-mongolia-sdk-go@v0.1.0
```

```go
import (
	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
	"github.com/gerege-systems/eid-mongolia-sdk-go/oidc"
)
```

## 1. RP бүртгүүлэх

RP-г eID Mongolia-гийн оператор бүртгэнэ — хүсэлтээ <eIDsupport@gerege.com>-оор гаргана. Баталсны дараа
**relyingPartyUUID** ба **API secret** (`rp_sk_…`) олгогдоно; secret **зөвхөн нэг удаа** харагдана. Шаардлагатай
мэдээлэл (байгууллага, зорилго `AUTH`/`SIGN`, `callbackHosts`, OIDC redirect URI…):
<https://developer.eidmongolia.mn/#registration>.

## 2. «eID-ээр нэвтрэх» (OpenID Connect)

Хамгийн хялбар нэвтрэлт: таны вэбэд нэг товч; нэвтрэх хуудсыг (QR · утсан дээрх аппаар нээх · регистрээр мэдэгдэл)
eID сервер өөрөө харуулж, гарын үсэг ба гэрчилгээний гинжийг шалгаад стандарт OIDC (Authorization Code + PKCE `S256`)
`id_token` өгнө. Утасны хөтчөөс дарахад хуудасгүйгээр шууд eID апп нээгдэнэ. Гэрээ:
<https://developer.eidmongolia.mn/#oidc>.

`client_id` = RP UUID, `client_secret` = RP API secret; RP-д `AUTH` эрх, OIDC асаалттай, `redirect_uri` (https)
бүртгэлтэй — **тэмдэгт бүрээрээ** таарна. Иргэний ETSI дугаар (`pnomn` claim) хэрэгтэй бол `PNOMN` эрх +
`Scope: "openid pnomn"`. eID-ийн OIDC нь зөвхөн confidential client (`client_secret_basic`) — native апп ч `code`-ийг
өөрийн backend-ээр солино.

```go
oc, err := oidc.NewClient(oidc.Config{
	ClientID:     os.Getenv("EID_RP_UUID"),
	ClientSecret: os.Getenv("EID_SECRET"), // rp_sk_… — зөвхөн backend
	RedirectURI:  "https://bank.example.mn/auth/eid/callback",
	// Issuer анхдагч https://login.eidmongolia.mn, Scope анхдагч "openid"
})
if err != nil {
	log.Fatal(err)
}

const txCookie = "eid_oidc_tx"

// GET /auth/eid/login — товчны href
http.HandleFunc("GET /auth/eid/login", func(w http.ResponseWriter, r *http.Request) {
	a, err := oc.CreateAuthorization(r.Context(), nil) // {URL, State, Nonce, CodeVerifier}
	if err != nil {
		http.Error(w, "eID түр ажиллахгүй байна", http.StatusBadGateway)
		return
	}
	tx, _ := json.Marshal(oidc.CallbackChecks{State: a.State, Nonce: a.Nonce, CodeVerifier: a.CodeVerifier})
	http.SetCookie(w, &http.Cookie{Name: txCookie, Value: base64.RawURLEncoding.EncodeToString(tx), Path: "/auth/eid",
		MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, a.URL, http.StatusFound)
})

// GET /auth/eid/callback?code&state (эсвэл ?error) — бүртгэлтэй redirect_uri
http.HandleFunc("GET /auth/eid/callback", func(w http.ResponseWriter, r *http.Request) {
	var checks oidc.CallbackChecks
	c, err := r.Cookie(txCookie)
	http.SetCookie(w, &http.Cookie{Name: txCookie, Path: "/auth/eid", MaxAge: -1, HttpOnly: true, Secure: true})
	if err == nil {
		raw, _ := base64.RawURLEncoding.DecodeString(c.Value)
		_ = json.Unmarshal(raw, &checks)
	}
	res, err := oc.HandleCallback(r.Context(), r.URL.Query(), checks) // state → token → id_token (ES256)
	if err != nil {
		code := oidc.ErrServerError
		var oe *oidc.Error
		if errors.As(err, &oe) {
			code = oe.Code // access_denied → «дахин оролдоно уу»; oe.Description-ийг логт л
		}
		http.Redirect(w, r, "/login?error="+url.QueryEscape(string(code)), http.StatusSeeOther)
		return
	}
	user := users.FindOrCreateBySub(res.Claims.Sub) // pairwise sub-аар таньна (нэрээр биш)
	startSession(w, user)                           // таны session-ийг ШИНЭЭР үүсгэ (session fixation)
	http.Redirect(w, r, "/", http.StatusSeeOther)
})
```

**Товч** — энгийн холбоос (`<a href>` эсвэл form GET); `fetch`/XHR/JS redirect биш — iOS Universal Link зөвхөн
хэрэглэгчийн tap-аас эхэлсэн redirect гинжид eID аппыг нээнэ.

```html
<a class="eid-login" href="/auth/eid/login">
  <img src="/img/eid-mongolia.png" alt="" width="20" height="20">
  eID Mongolia-аар нэвтрэх
</a>
```

Лого: <https://developer.eidmongolia.mn/logo-96.png>-ийг татаж өөрийн хостоос үйлчил. Саармаг (цагаан, хүрээтэй)
товч — бусад нэвтрэх товчтой зэрэгцэж болно. `CreateAuthorization(ctx, &oidc.AuthorizationOptions{Display: "page"})` —
утсан дээр ч нэвтрэх хуудас (QR / push), ж: таблет киоск.

**Claims** (`oidc.Claims`): `Sub` (pairwise), `Acr` (`oidc.ACRQualified` | `oidc.ACRAdvanced`), `AuthTime`,
`GivenName` / `FamilyName` (латин), `GivenNameMN` / `FamilyNameMN` (кирилл, байвал), `PNOMN` (`pnomn` scope + эрхтэй
үед). `id_token` 5 минут; access_token / refresh_token / userinfo байхгүй — нэвтэрсний дараа өөрийн session.

**Аюулгүй байдал (OIDC).**

- `State`, `Nonce`, `CodeVerifier`-ийг **хөтчийн session-тэй** (httpOnly, Secure, SameSite=Lax cookie эсвэл server
  session) холбож хадгална; `HandleCallback` state-ийг constant-time тулгаж, таарахгүй бол code-ийг солихгүй
  (`state_mismatch`). Үүнгүйгээр login CSRF (халдагчийн бүртгэлд хохирогчийн eID) нээлттэй.
- `HandleCallback` / `VerifyIDToken` нь ES256 гарын үсэг (JWKS `kid`, 1 цаг cache, танихгүй `kid` → нэг удаа дахин
  татна; `alg` нь зөвхөн `ES256`), `iss`, `aud` (= `ClientID`; олон aud бол `azp`), `exp` / `iat` (±60 сек), `nonce`-ийг
  шалгана. `ErrInvalidIDToken` гарвал **итгэхгүй**.
- Code нэг удаагийн, 60 секунд — callback-ийг дахин ачаалбал `invalid_grant` → дахин нэвтрүүлнэ.
- **Native апп (RFC 8252):** authorize-ийг системийн хөтчөөр (iOS `ASWebAuthenticationSession`, Android Custom Tabs)
  нээнэ, **WebView хориотой**; `redirect_uri` = https Universal Link / App Link.

## 3. RP-API client

```go
c, err := eid.NewClient(eid.Config{
	// BaseURL анхдагч https://rp.eidmongolia.mn (RP-API, /v3-гүй) — mTLS-тэй RP ч мөн энэ хост
	Credentials: eid.Credentials{
		RPUUID:    os.Getenv("EID_RP_UUID"),
		RPName:    "Интернэт банк", // дэд системийн нэр, ≤ 120 тэмдэгт
		APISecret: os.Getenv("EID_SECRET"),
	},
	Trust: eid.TrustConfig{
		TrustAnchorsPEM:  []string{eid.NationalRootCAPEM}, // Mongolian National Root CA (01) — production-д ЗААВАЛ
		IntermediatesPEM: intermediatePEMs,               // 02 MDDC → 03 Gerege → 04 eID Mongolia Issuing CA
	},
})
```

Бүх дуудлага `context.Context` авна (цуцлалт, deadline); дуудлага бүрийн анхдагч хугацаа `Config.Timeout` (15s),
long-poll ба PDF өөрийн уртыг хэрэглэнэ. Завсрын CA-уудын эх: <https://developer.eidmongolia.mn/#verification>.

### 3.1. Нэвтрэлт — push

```go
s, err := c.Auth.NotificationByEtsi(ctx, "PNOMN-12345678", // ETSI / регистр / иргэний дугаар (сервер танина)
	[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "Интернэт банкинд нэвтрэх"}}, nil)
show(s.VC) // 5 оронтой баталгаажуулах код — ПИН БИШ, зөвхөн харуулна

r, err := c.Session.WaitForResult(ctx, s.SessionID, nil) // long-poll; хугацаа дуусвал RUNNING-ийг алдаагүй буцаана
who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{ExpectedFlowType: eid.FlowNotification})
if err != nil {
	return err // *eid.SessionFailedError (USER_REFUSED, TIMEOUT…) эсвэл *eid.ValidationError — ИТГЭХГҮЙ
}
if err := c.Validator.CheckRevocation(ctx, who.Certificate); err != nil { // TrustConfig.Revocation тохируулсан бол
	return err
}
log.Println(who.DocumentNumber, who.Subject.SerialNumber, who.Subject.GivenName, who.Subject.Surname)
```

### 3.2. QR ба ижил төхөөрөмж — device link v3

Иргэн өөр дэлгэц дээрх **QR**-ийг утсаараа уншина, эсвэл RP-ийн сайт eID апптай **ижил утсан** дээр нээгдсэн бол товчоор
аппыг нээнэ. **Ижил төхөөрөмжид Web2App (device link v3) урсгалыг хэрэглэ** — утасны хөтчөөс товч дарахад апп шууд
нээгдэж, баталгаажуулсны дараа таны `CallbackURL` руу `userChallengeVerifier`-тэй буцна. (RP-ийн native аппаас бол
App2App.) Legacy `/dl?sessionId&vc` холбоос 2026-10-07-нд серверээс хасагдсан — SDK-д байхгүй.

```go
// backend — session эхлүүлээд бүх хариуг СЕРВЕРТ хадгална (SessionToken/SessionSecret/ReceivedAt/ACSP)
s, err := c.Auth.DeviceLinkAnonymous(ctx,
	[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "Интернэт банкинд нэвтрэх"}},
	&eid.AuthOptions{CallbackURL: "https://bank.example.mn/auth/eid/callback?tx=" + txID}) // товч харуулах бол; host = callbackHosts
store.Put(s.SessionID, s) // браузерт ЗӨВХӨН SessionID, VC

link := func(s *eid.DeviceLinkSession, t eid.DeviceLinkType) (string, error) {
	return eid.BuildDeviceLink(eid.DeviceLinkInput{
		DeviceLinkBase: s.DeviceLinkBase, DeviceLinkType: t,
		SessionToken: s.SessionToken, SessionSecret: s.SessionSecret,
		SessionType: eid.SessionAuth, Lang: "mon", ReceivedAt: s.ReceivedAt,
		RPChallenge: s.ACSP.RPChallenge, RelyingPartyName: s.ACSP.RelyingPartyName,
		Interactions: s.ACSP.Interactions, InitialCallbackURL: s.ACSP.InitialCallbackURL, // QR-д authCode-д орохгүй
	})
}

// GET /eid/qr?sessionId=… — браузер 1 секунд тутам дуудаж QR-ийг дахин зурна (QR ~20 сек хүчинтэй)
http.HandleFunc("GET /eid/qr", func(w http.ResponseWriter, r *http.Request) {
	s := store.Get(r.URL.Query().Get("sessionId")) // өөрийн browser session-д хамаарахыг шалга
	l, err := link(s, eid.LinkQR)
	if err != nil {
		http.Error(w, "session дууссан", http.StatusGone)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"link": l})
})
// гар утсанд: товчны href = link(s, eid.LinkWeb2App) (нэг удаа угсарна)
```

SSE/WebSocket-оор түлхэх бол `eid.TickQRDeviceLink(ctx, input, time.Second, send)` — шууд нэг, дараа нь секунд тутам;
`ctx`-ийг цуцалж зогсооно.

**Харуулсан төрлөө заавал тулга (relay хаалт):**

```go
// QR хуудас → poll-оор дууссан үр дүн
who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{ExpectedFlowType: eid.FlowQR})

// Web2App товч → callback (?userChallengeVerifier=…) ирсний дараа
who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{
	ExpectedFlowType:      eid.FlowWeb2App, // RP-ийн апп дахь товч бол eid.FlowApp2App
	UserChallengeVerifier: callback.Query().Get("userChallengeVerifier"),
})
```

QR ба товч хоёуланг нэг хуудсанд: НЭГ session (`CallbackURL`-тай), callback-аар ирснийг `Web2App`/`App2App`-аар,
poll-оор ирснийг `QR`-аар шалга.

### 3.3. Гарын үсэг (digest)

```go
digest := eid.SHA256Base64(docBytes)
s, err := c.Sign.DigestByEtsi(ctx, "PNOMN-12345678", digest,
	[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "Зээлийн гэрээнд гарын үсэг зурах"}}, nil)
show(s.VC)
r, err := c.Session.WaitForResult(ctx, s.SessionID, nil)
sig, err := c.Validator.ValidateSign(r, digest, eid.SHA256) // digest-ийн эсрэг

// device-link / push-оор эхлүүлсэн бол урсгалаа тулга (ValidateAuth-тай ижил; зөрвөл *ValidationError)
sig, err = c.Validator.ValidateSign(r, digest, eid.SHA256, eid.ValidateSignOptions{ExpectedFlowType: eid.FlowQR})
```

RAW_DIGEST_SIGNATURE-д `flowType` гарын үсэгт ордоггүй (зөвхөн digest зурагдана) — энэ нь RP-API хариуны тулгалт.

### 3.4. PDF (PAdES, CA угсарна) ба байгууллагын нэрийн өмнөөс

Иргэн **өөрийн PIN2 гэрчилгээгээр** зурна; байгууллагыг төлөөлөх эрхийг eID өөрийн бүртгэлээр шалгана (хувь хүний
квалификацтай гарын үсэг — байгууллагын тамга биш).

```go
reps, err := c.Organization.GetRepresentations(ctx, "PNOMN-12345678") // иргэн сүүлийн 24 цагт нэвтэрсэн байх
s, err := c.PDF.Prepare(ctx, eid.PDFPrepareInput{
	PDF: pdfBytes, FileName: "Гэрээ №12.pdf",
	Signer: eid.PDFSignerRef{Etsi: "PNOMN-12345678"}, Flow: eid.PDFFlowNotification,
	OnBehalfOf: "NTRMN-6235972", // заавал биш
})
show(s.VC) // s.Digest — хоёр урсгалд (ValidateSign-д); device-link-д s.DeviceLink, s.Interactions (BuildDeviceLink, SessionSign)
r, err := c.Session.WaitForResult(ctx, s.SessionID, nil)
if r.EndResult != eid.EndResultOK || r.PDF == nil || r.PDF.DocumentStatus != eid.PDFReady ||
	r.PDF.Signer == nil || r.PDF.Signer.OnBehalfOf != "NTRMN-6235972" {
	return errors.New("PDF гарын үсэг амжилтгүй")
}
signed, err := c.PDF.Document(ctx, s.SessionID)
if !eid.DocumentVerified(signed, r.PDF) { // SHA-256 = pdf.outSha256, READY
	return errors.New("татсан PDF session-ий outSha256-тай таарсангүй")
}
```

`OnBehalfOf` татгалзвал `*eid.ForbiddenError` / `*eid.APIError`-ийн `Code` (`eid.OnBehalfErrorCodes`):
`REPRESENTATION_DENIED`, `REPRESENTATION_PENDING`, `REPRESENTATION_EXPIRED`, `ORG_NOT_ACTIVE`, `SIGNER_UNIDENTIFIED`
(403) · `ORG_NOT_FOUND` (404) · `REPRESENTATION_REVOKED` (403, document татах үед).

## 4. Аюулгүй байдал — яагаад `Validator` заавал

`EndResult == "OK"` гэдэгт **дангаар нь итгэхгүй** — RP-API эвдэрсэн/proxy хийгдсэн бол хуурамч OK ирж болзошгүй.
`Validator` (<https://developer.eidmongolia.mn/#verification>):

1. `State == COMPLETE && EndResult == OK` (эс бөгөөс `*SessionFailedError`).
2. Иргэний гэрчилгээг **trust anchor (Mongolian National Root CA, `eid.NationalRootCAPEM`)** хүртэл гинжээр
   (Root 01 → National Issuing CA 02 → Gerege Issuing CA 03 → eID Mongolia Issuing CA 04 → иргэн): issuer нэр,
   AKI/SKI, CA basicConstraints, гарын үсэг, хугацаа. Trust anchor тохируулаагүй бол **fail-closed**
   (`AllowUntrusted` зөвхөн dev/тест). OS-ийн trust store-д итгэхгүй.
3. Гэрчилгээ хүчинтэй хугацаанд (`ClockSkew`) + шаардсан түвшин (`RequiredLevel`, анхдагч `QUALIFIED`; `QSCD` хангана).
4. Гарын үсэг (`rsassa-pss` / `shaNNNWithRSAEncryption` / `ecdsa-with-SHA256`):
   - **auth** → ACSP_V2 payload (`smart-id|ACSP_V2|serverRandom|rpChallenge|userChallenge|B64(rpName)|B64(brokeredRpName)|B64(SHA-256(interactions))|interactionTypeUsed|initialCallbackUrl|flowType`),
     hash = хүсэлтийн `HashAlgorithm`; `flowType` санал болгосон урсгалд, `ExpectedFlowType` өгвөл ЯГ таарах,
     Web2App/App2App-д `UserChallengeVerifier` заавал; `initialCallbackUrl` нь `""` эсвэл таны callback л.
   - **sign** → таны digest дээр (prehashed); `ValidateSignOptions.ExpectedFlowType` өгвөл хариуны `flowType` ЯГ таарах
     (гарын үсэгт ордоггүй — хариуны тулгалт).
   - Алгоритм ↔ түлхүүрийн төрөл тулгана (RSA нэр зөвхөн RSA гэрчилгээтэй); hash нь хүссэнтэй ЯГ таарна (downgrade
     хаалт). ECDSA нь зөвхөн `ecdsa-with-SHA256` + EC P-256 + SHA-256 session (CA-ийн ECDSA credential SHA-256-аас
     өөрийг зурдаггүй; SHA-384/512 session-д ECDSA хариу ирвэл `ValidationError`).
5. Цуцлалт — `TrustConfig.Revocation` (OCSP/CRL hook, `RevocationHardFail` анхдагч) → `CheckRevocation`.
   QUALIFIED non-repudiation-д RP тохируулна.

Аль нэг алхам бүтэлгүйтвэл `*eid.ValidationError` — хариунд **итгэхгүй**.

## 5. Алдааны төрлүүд (`errors.As`)

| Алдаа | Утга |
|---|---|
| `*eid.AuthenticationError` | 401 — API secret буруу/байхгүй |
| `*eid.ForbiddenError` | 403 — IP allowlist / mTLS / RP-ийн эрх; `OnBehalfOf` татгалзвал `.Code` |
| `*eid.APIError` | бусад HTTP алдаа (`.Status`, `.Body`, `.Code` — ж: 404 `ORG_NOT_FOUND`) |
| `*eid.NetworkError` | сүлжээ / timeout (`.Timeout`, `Unwrap` → `context.DeadlineExceeded` г.м.) |
| `*eid.SessionFailedError` | endResult ≠ OK (`TIMEOUT`, `USER_REFUSED…`) — `.EndResult` |
| `*eid.ValidationError` | гинж / гарын үсэг / түвшин / урсгалын шалгалт унасан |
| `*eid.DeviceLinkError` | device link угсрах боломжгүй (оролтын хэлбэр) |
| `*oidc.Error` | OIDC — `.Code`: `access_denied`, `login_required`, `state_mismatch`, `invalid_grant`, `invalid_id_token`, `server_error` … |

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

## Хөгжүүлэлт

```bash
go vet ./... && go test -race ./...
```

Тест: CA серверийн device link golden векторууд (`testdata/devicelink_golden.json`, TS SDK-тэй ижил файл), Smart-ID
ACSP_V2 вектор, RFC 7636 PKCE вектор, бодит нийтийн CA гэрчилгээнүүд.

---

## English

Go relying-party SDK for **eID Mongolia** — feature parity with the TypeScript SDK, standard library only (Go ≥ 1.22).

- `eid.NewClient(eid.Config{…})` — RP-API v3: `Auth` (push / device link), `Sign` (raw digest), `PDF` (PAdES, CA-assembled,
  `OnBehalfOf`), `Organization`, `Session` (long-poll), `Validator`. Every call takes a `context.Context`.
- `eid.BuildDeviceLink` — device link v3 (QR / Web2App / App2App) with HMAC `authCode`, byte-identical to the server
  golden vectors. Prefer **Web2App** for same-device sign-in; the legacy `/dl?sessionId&vc` link is gone.
- `Validator.ValidateAuth` / `ValidateSign` — certificate chain to the Mongolian National Root CA
  (`eid.NationalRootCAPEM`), validity, level, ACSP_V2 / digest signature (RSA-PSS, PKCS#1 v1.5, ECDSA P-256/SHA-256), flow-type relay
  guard; `CheckRevocation` with your OCSP/CRL hook. Never trust `endResult == OK` alone.
- `eid.DocumentVerified` — downloaded PDF SHA-256 equals the session's `pdf.outSha256`.
- `oidc.NewClient` — "Sign in with eID" (OpenID Connect, code + PKCE S256, `client_secret_basic`), ES256 `id_token`
  verification with JWKS caching (`iss`, `aud`/`azp`, `exp`/`iat` ±60 s, `nonce`).
- Typed errors via `errors.As`. RP registration: <eIDsupport@gerege.com>. Docs: <https://developer.eidmongolia.mn/#overview>.

License: MIT.
