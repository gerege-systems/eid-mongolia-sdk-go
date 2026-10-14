# eid-mongolia-sdk-go

**eID Mongolia** relying-party SDK for Go — иргэнийг утсаар нь нэвтрүүлэх (authentication) ба хууль ёсны цахим гарын
үсэг (qualified signature) зуруулах, «eID-ээр нэвтрэх» товчны backend. RP-API v3, Smart-ID нийцтэй.
TypeScript хувилбартай ([gerege-systems/eid-mongolia-sdk](https://github.com/gerege-systems/eid-mongolia-sdk))
функциональ ижил. Бүрэн баримт: <https://developer.eidmongolia.mn/#overview>.

> SDK **backend**-д ажиллана: бүх дуудлага API secret (`rp_sk_…`)-ээр баталгаажна. Secret, `SessionSecret`-ийг
> браузер/гар утсанд хэзээ ч бүү гарга — браузерт зөвхөн таны backend-ийн өгсөн холбоос / QR / товч харагдана.

- Go ≥ 1.25. `eid`, `eidlogin` нь **зөвхөн стандарт сан** импортлодог; `pades` (PDF) нь digitorus/pdf, pkcs7, timestamp,
  x/crypto.
- Багц: `eid` (RP-API, device link, validator, PDF), `eid/eidlogin` («eID-ээр нэвтрэх» товчны net/http handler),
  `pades` (клиент талын PAdES — PDF eID-ийн серверт очихгүй; native SDK-уудын reference).

[English summary](#english)

## Суулгах

```bash
go get github.com/gerege-systems/eid-mongolia-sdk-go@v0.2.0
```

```go
import (
	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
	"github.com/gerege-systems/eid-mongolia-sdk-go/eidlogin"
)
```

## 1. RP бүртгүүлэх

RP-г eID Mongolia-гийн оператор бүртгэнэ — хүсэлтээ <eIDsupport@gerege.com>-оор гаргана. Баталсны дараа
**relyingPartyUUID** ба **API secret** (`rp_sk_…`) олгогдоно; secret **зөвхөн нэг удаа** харагдана. Шаардлагатай
мэдээлэл (байгууллага, зорилго `AUTH`/`SIGN`, `callbackHosts`…):
<https://developer.eidmongolia.mn/#registration>.

## 2. «eID-ээр нэвтрэх» — нэг товч (`eidlogin`)

Smart-ID-тэй RP-үүдийн хэв маяг: хөтөчид **нэг товч**, бүх eID дуудлага таны backend-д (API secret-ээр).
`eidlogin.Handler` (net/http) нь §3.1/§3.2-ийн RP-API (device link v3, push, `Validator`)-ийг л ашигладаг бэлэн урсгал;
хөтчийн товч нь TS SDK-ийн Web Component `<eid-login-button>` (`@gerege-systems/eid-mongolia-sdk/button`) — хариуны
хэлбэр TS-ийн `createEidLogin`-тэй ижил.

| | Хүсэлт | Хариу |
|---|---|---|
| `POST /auth/eid/start` | `{"mode":"qr"}` эсвэл `{"mode":"push","idCode":"УБ12345678"}` (JSON заавал) | `{mode, vc, qr?, expiresIn}` + `Set-Cookie: eid_login` |
| `GET /auth/eid/start?mode=web2app` | утасны хөтөч (товчны навигаци) | `302` → eID апп (Web2App) |
| `GET /auth/eid/status` | cookie | `PENDING` (+шинэ `qr`) · `WAIT_CALLBACK` · `OK` (`redirect`, `data`) · `FAILED` (`error`) · `EXPIRED` |
| `GET /auth/eid/callback` | апп буцаана: `?sessionId&userChallengeVerifier` | `303` → `Success.Redirect` / `SuccessRedirect`, алдаа бол `FailureRedirect?eid_error=<код>` |

eID сервер Web2App буцах замыг үргэлж `/auth/eid/callback` болгож нормчилдог тул `/auth/eid/` дор mount хийнэ:

```go
c, _ := eid.NewClient(eid.Config{
	Credentials: eid.Credentials{RPUUID: uuid, RPName: "Интернэт банк", APISecret: secret},
	Trust:       eid.TrustConfig{TrustAnchorsPEM: []string{eid.NationalRootCAPEM}, IntermediatesPEM: intermediates},
})
login, err := eidlogin.New(eidlogin.Config{
	Client:      c,
	CallbackURL: "https://bank.example.mn/auth/eid/callback", // host нь callbackHosts-д; утасны урсгалд заавал
	OnSuccess: func(w http.ResponseWriter, r *http.Request, id *eidlogin.Identity) (*eidlogin.Success, error) {
		// id.ETSI (PNOMN-…) — хэрэглэгчийг ҮҮГЭЭР таньна; id.GivenName/Surname (латин), id.Person (кирилл, байвал)
		// id.SessionID, id.DocumentNumber, id.Certificate — дараагийн алхамд (гарын үсэг, гэрчилгээ холбох)
		u, err := users.FindOrCreateByETSI(r.Context(), id.ETSI)
		if err != nil {
			return nil, err
		}
		sid, err := sessions.Create(r.Context(), u.ID) // ШИНЭ session (session fixation)
		if err != nil {
			return nil, err
		}
		http.SetCookie(w, &http.Cookie{Name: "app_session", Value: sid, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		return &eidlogin.Success{Redirect: "/dashboard"}, nil
	},
	ClientIP: eidlogin.ForwardedClientIP(1), // nginx/LB нэг hop-ийн ард; proxy-гүй бол eidlogin.RemoteAddrIP
	// Store: redisStore,        // олон instance бол (анхдагч — процессын санах ой)
	// RateLimit: …              // "start:<ip>", "push:<idCode>"; анхдагч зөвхөн push 3/мин нэг дугаарт
})
if err != nil {
	log.Fatal(err)
}
mux.Handle("/auth/eid/", login)
```

Хөтөчид:

```html
<script type="module" src="https://cdn.jsdelivr.net/npm/@gerege-systems/eid-mongolia-sdk@0.14.1/dist/button.js"></script>
<eid-login-button start-url="/auth/eid/start" status-url="/auth/eid/status" lang="mn"></eid-login-button>
```

Desktop дээр цонх (QR секунд тутам шинэчлэгдэнэ + регистрээр push), утсан дээр eID апп шууд нээгдэнэ. Амжилттай бол
`eid-login-success` үйл явдал ба `redirect` руу шилжилт.

**Аюулгүй байдал.**

- `SessionToken`, `SessionSecret`, `rpChallenge` серверт (`Store`); хөтөчид зөвхөн HttpOnly, Secure, SameSite=Lax cookie
  (`<sessionId>.<binding>`, store-д SHA-256). Status ба callback зөвхөн нэвтрэлтийг **эхлүүлсэн хөтөчид** — өөр хөтчид нээгдсэн
  callback URL (verifier-тэй ч) хүлээн авагдахгүй (login CSRF).
- `start` POST нь JSON заавал (cross-origin preflight), `Sec-Fetch-Site: cross-site` → 403.
- `OK` нь зөвхөн `Validator.ValidateAuth` амжилттай үед: QR → `FlowQR`, push → `FlowNotification`, утас → `FlowWeb2App` +
  `userChallengeVerifier`. Web2App session-ийг poll дуусгахгүй (`WAIT_CALLBACK`). `OnSuccess` нэг session-д нэг л удаа
  (`Store.Delete` атомар — Redis `DEL`).
- `Success.Data` хөтөчид очно — нууц бүү оруул. Push-ийн eID алдаа ерөнхий (`eid_unavailable`) — иргэн бүртгэлтэй эсэхийг задлахгүй.
- `OnSuccess`-ээс ӨМНӨ tx store-оос атомар устгагдана (нэг удаагийн баталгаа) — `OnSuccess` дотор store-оос бүү унш;
  хэрэгтэй бүхэн `Identity`-д (`SessionID`, `DocumentNumber`, `Certificate`, …).

**Клиент IP** (`start:<ip>` хязгаар) — `Config.ClientIP`. Итгэмжит reverse proxy-ийн ард `eidlogin.ForwardedClientIP(n)`:
`X-Forwarded-For`-ийн **баруунаас n** дахь утга (n = таны proxy-ийн тоо), XFF байхгүй бол `X-Real-IP`, hop дутвал `""`.
Proxy-гүй бол `eidlogin.RemoteAddrIP`. nil бол IP-ээр хязгаарлахгүй (`New` нэг удаа Warn бичнэ). Анхдагч `RateLimit` зөвхөн
`push:`-ийг хязгаарладаг — `start:<ip>`-ийг өөрийн `RateLimit`-ээр. TS SDK-ийн `trustProxy` / `getClientIp`-тэй ижил дүрэм.

**Redis store** (SDK нэмэлт хамааралгүй — жишээ нь `github.com/redis/go-redis/v9`):

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

// DEL атомар — зэрэг хоёр status-ийн зөвхөн нэг нь OnSuccess дуудна.
func (s redisStore) Delete(ctx context.Context, sid string) (bool, error) {
	n, err := s.rdb.Del(ctx, s.key(sid)).Result()
	return n == 1, err
}
```

Tx-д `SessionSecret` (QR угсрах материал) байдаг — Redis-ийг сүлжээнээс хаалттай, TLS/AUTH-тай ашигла.

**eID аппын доод хувилбар.** `flowType` бэхлэлт (device link v3) ба Web2App-ийн `userChallengeVerifier` нь
**iOS 2.2.3 (build 59)**, **Android 2.2.3 (versionCode 60)**-аас эхэлсэн. eID сервер 2026-10-07-оос legacy холбоосыг
бүрэн хассан (v3-гүй session-д утас `DEVICE_LINK_REQUIRED`) бөгөөд доод хувилбарыг `/mobile/app-config`-оор албадан
шинэчлүүлдэг: Android 2026-10-07-оос ≥ 70, 2026-10-14-ний байдлаар iOS ≥ 2.2.7, Android ≥ 83
(`curl https://ca.eidmongolia.mn/mobile/app-config`). Иймд гарын үсэг зурж чадах бүх апп эдгээрийг дэмжинэ. Эх сурвалж:
eID CA-ийн `docs/DEVICE_LINK_V3.md` §5, §7; changelog `2026-10-02-ios-min-version-2-2-3`, `2026-10-07-android-min-70`.

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
long-poll өөрийн уртыг, PAdES prepare / баримт татах `Config.PDFTimeout`-ийг (анхдагч 80s) хэрэглэнэ. Завсрын CA-уудын эх: <https://developer.eidmongolia.mn/#verification>.

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
// SignOptions.FileName — баримтын нэр CA-ийн /verify хуудас, иргэний түүхэнд харагдана (заавал биш)

// device-link / push-оор эхлүүлсэн бол урсгалаа тулга (ValidateAuth-тай ижил; зөрвөл *ValidationError)
sig, err = c.Validator.ValidateSign(r, digest, eid.SHA256, eid.ValidateSignOptions{ExpectedFlowType: eid.FlowQR})
```

RAW_DIGEST_SIGNATURE-д `flowType` гарын үсэгт ордоггүй (зөвхөн digest зурагдана) — энэ нь RP-API хариуны тулгалт.

**QR / Web2App / App2App** — `c.Sign.DeviceLinkByEtsi` / `DeviceLinkByDocument` (`SignOptions.CallbackURL`-тай бол
Web2App/App2App); холбоосыг `eid.BuildDeviceLink(s.LinkInput(eid.LinkQR, "mon"))` (auth/cert session-д ч мөн).
`s.Sign` (`SignContext`: digest, hash, алгоритм, interactions, callback)-ийг session-тэй хамт серверт хадгал.

**`ExpiresAt`** — session дуусах мөч: CA-ийн session start хариуны `expiresAt` (RFC 3339; auth / sign / certificate-choice
бүгдэд, 2026-10-14-өөс). Хуучин CA (талбаргүй) үед sign / certificate-choice-д SDK тооцоолно — CA-ийн анхдагч 600с
(`eid.DefaultSignSessionTTL`; CA админ 60–1800с → `Config.SignSessionTTL`), auth-д тэг. Эцсийн үнэн нь `GET /session`
(`TIMEOUT`).

**Session эхлэх алдаа** (`*eid.APIError`, `errors.Is`-ээр): `eid.ErrNoSigningCertificate` — 409 `NO_SIGNING_CERTIFICATE`
(sign / certificate-choice start, `/pdf/sign/prepare`: иргэнд идэвхтэй төхөөрөмж / хүчинтэй гарын үсгийн гэрчилгээ алга,
session үүсээгүй); `eid.ErrCertChoiceInvalid` — 409 `CERT_CHOICE_INVALID` (linked sign-ийн certificate-choice хүчингүй /
хуучирсан / ашиглагдсан → дахин эхлүүл); `eid.ErrRequestInvalid` — 400 `REQUEST_INVALID` (ж: linked-д `linkedSessionID` дутуу).

**Гэрчилгээг урьдчилж мэдэх (client-side PAdES / CMS)** — гэрчилгээ DTBS-д (`signingCertificateV2`) ордог тул эхлээд
certificate-choice, дараа нь digest-ийг **яг тэр төхөөрөмж рүү (`documentNumber`)** зуруулна. Олон утастай иргэнд
etsi-ээр эхлүүлбэл өөр утас зурж, гарын үсэг гэрчилгээтэйгээ таарахгүй.

```go
cc, err := c.Sign.CertificateChoiceByEtsi(ctx, "PNOMN-12345678", nil) // эсвэл CertificateChoiceDeviceLink (зөвхөн QR)
r, err := c.Session.WaitForResult(ctx, cc.SessionID, nil)
signer, err := c.Validator.ValidateCertificateChoice(r, cc.SessionID) // Signer{Certificate, DocumentNumber}
dtbs := buildDTBS(signer.Certificate)                                 // 32 байт SHA-256, стандарт base64
s, err := c.Sign.DigestForSigner(ctx, signer, dtbs, ix, &eid.SignOptions{FileName: "Гэрээ.pdf"}) // linked/{documentNumber}
// QR / Web2App: c.Sign.DeviceLinkForSigner(ctx, signer, dtbs, ix, &eid.SignOptions{CallbackURL: …})
r, err = c.Session.WaitForResult(ctx, s.SessionID, nil)
sig, err := c.Validator.ValidateSign(r, s.Sign.Digest, s.Sign.HashAlgorithm, eid.ValidateSignOptions{
	ExpectedFlowType:    eid.FlowNotification,
	ExpectedAlgorithm:   s.Sign.SignatureAlgorithm, // sha256WithRSAEncryption — PSS хариуг татгалзана
	ExpectedCertificate: signer.Certificate,        // өөр гэрчилгээгээр зурсан бол татгалзана
})
```

`DigestForSigner` / `DeviceLinkForSigner`-ийн анхдагч: `sha256WithRSAEncryption` + `SHA-256` (CA SplitKey RSA нь хүссэн
алгоритмаар, PKCS#1 v1.5; хуучин threshold-ECDSA credential нь үргэлж `ecdsa-with-SHA256` — `ExpectedAlgorithm` үүнийг
зөвхөн EC P-256 гэрчилгээтэй үед зөвшөөрнө). Digest-ийн урт hash-тай таарахгүй бол хүсэлт явахгүй.

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

Түр алдаа — `*eid.APIError.Retryable()` үнэн, `RetryAfter`-ийн (CA-ийн `Retry-After`, секунд эсвэл огноо) дараа
давтана: prepare 429 `PDF_PREPARE_BUSY`, 503 `LTV_UNAVAILABLE` / `TSA_UNAVAILABLE`; document 503 `DOCUMENT_PENDING`,
`TSA_UNAVAILABLE`, `LTV_UNAVAILABLE`. `Header` — хариуны бүх header.

`PDF.Document` санах ойд `Config.PDFMaxBytes` (анхдагч `eid.DefaultPDFMaxBytes` = 64 MiB) хүртэл уншина; хэтэрвэл
`*eid.ResponseTooLargeError`. JSON хариу 4 MiB-ээс хэтэрвэл мөн `*eid.ResponseTooLargeError` (таслахгүй).
`GetRepresentations`-ийн `Raw` — серверийн түүхий JSON.

**Хүнд харуулахдаа `RoleLabel` / `RightTypeLabel` / `SourceLabel` ашигла** (`Representation`-д гурвуулаа, session-ий
`OnBehalfOf`-д `RoleLabel` / `RightTypeLabel` — тэнд `Source` байхгүй) — `Role` (`ceo` / `founder` / `stakeholder` эсвэл
MANAGER-т бичсэн текст), `RightType` (`ADMIN` | `MANAGER`), `Source` (`REGISTRY` | `MANUAL`) нь машин утга, өөрөө
орчуулахгүй. Хэл: `eid.Config{…, Language: "en"}` → дуудлага бүрд `Accept-Language`; `""` = илгээхгүй (сервер mn).
Хуучин CA-д хоосон.

### 3.5. Session-ий person блок

```go
r, _ := c.Session.WaitForResult(ctx, s.SessionID, nil)
who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{})
if err == nil && eid.PersonMatchesCertificate(r.Person, who.Subject) {
	// r.Person: FirstName (нэр), LastName (ЭЦГИЙН нэр), FamilyName (УРГИЙН овог), CivilID, RegNo, BirthDate, Gender, GeID
}
// r.Raw — серверийн түүхий JSON (SDK задлаагүй талбарт)
```

Person блок гарын үсэгт **ордоггүй** — гэрчилгээний `SERIALNUMBER` (`PNOMN-<civilId>`)-тэй тулгаж байж итгэнэ.

### 3.6. Иргэний PKI самбар (`PKI_READ` эрх)

`c.Person.Certificates` · `Devices` · `Activity(ctx, etsi, &eid.ActivityQuery{Flow, Limit, Offset})` · `Summary` ·
`Children` — иргэн сүүлийн 24 цагт танай RP-ээр нэвтэрсэн байх ёстой (эс бөгөөс 403). Хариу бүрт `Raw`.

### 3.7. USB токен

```go
// гэрчилгээ олголт (TOKEN_ISSUE эрх) — иргэн утсаараа PIN2-оор батална
st, err := c.Token.IssueCertificate(ctx, eid.TokenCertInput{SignerEtsi: etsi, CSRAuth: csrA, CSRSign: csrS,
	TokenSerial: "EP2003-0042A1", OnBehalfOf: ""}) // "" = хувийн токен
// … c.Session.Poll → r.TokenCertificate.Status == eid.TokenCertIssued
res, err := c.Token.CertificateResult(ctx, st.SessionID)
err = eid.VerifyTokenCertificates(res, csrA, csrS) // гэрчилгээ бүр CSR-ийн түлхүүртэй
if l, ok := eid.TokenLimitOf(err); ok { /* 409 TOKEN_LIMIT_REACHED: l.Kind, l.Limit, l.Organization */ }

// токеноор нэвтрэх (AUTH эрх)
ch, err := c.Token.AuthChallenge(ctx)
digest, _ := eid.TokenAuthDigest(ch.RPUUID, ch.Challenge) // токен CKM_ECDSA → түүхий r||s
who, err := c.Token.AuthVerify(ctx, ch.ChallengeID, authCertDER, rs)

// токеноор PDF (PAdES, SIGN эрх) — session/утасгүй; байгууллагын токенд OnBehalfOf = тухайн байгууллага
p, err := c.PDF.TokenPrepare(ctx, eid.PDFTokenPrepareInput{PDF: pdfBytes, FileName: "Гэрээ.pdf",
	SignerEtsi: etsi, Certificate: signCertDER})
var rs []byte // токен (PKCS#11): CKM_ECDSA(p.HashToSign) → түүхий r||s, 64 байт — p.ExpiresAt хүртэл
blk, err := c.PDF.TokenFinalize(ctx, p.SigningID, rs) // READY блок; 503 DOCUMENT_PENDING → ижил rs-ийг дахин
signed, err := c.PDF.TokenDocument(ctx, p.SigningID)
if !eid.DocumentVerified(signed, blk) { /* итгэхгүй */ }
```

`/token/auth/*`, `/pdf/token/*` нь CA-д байгаа ч `/.well-known/eid`-д хараахан жагсаагдаагүй (гэрээний тест WARN).

## 4. Аюулгүй байдал — яагаад `Validator` заавал

`EndResult == "OK"` гэдэгт **дангаар нь итгэхгүй** — RP-API эвдэрсэн/proxy хийгдсэн бол хуурамч OK ирж болзошгүй.
`Validator` (<https://developer.eidmongolia.mn/#verification>):

1. `State == COMPLETE && EndResult == OK` (эс бөгөөс `*SessionFailedError`).
2. Иргэний гэрчилгээг **trust anchor (Mongolian National Root CA, `eid.NationalRootCAPEM`)** хүртэл гинжээр
   (Root 01 → National Issuing CA 02 → Gerege Issuing CA 03 → eID Mongolia Issuing CA 04 → иргэн) — Go-ийн
   `x509.Certificate.Verify` (RFC 5280): CA basicConstraints + **pathLenConstraint** (04 нь `pathlen:0`), CA-ийн
   keyUsage keyCertSign, **name constraints**, **EKU** (auth → clientAuth, sign → emailProtection — CA-ийн профайл;
   завсрын CA-д EKU байвал түүнд багтах), үл таних **critical extension** → татгалзана, гарын үсэг, хугацаа (гинжийг
   leaf-ийн хүчинтэй хугацаанд, `ClockSkew`-ийн хүрээнд). Trust anchor тохируулаагүй бол **fail-closed**
   (`AllowUntrusted` зөвхөн dev/тест). OS-ийн trust store-д итгэхгүй. `IntermediatesPEM`-д 02, 03, 04-ийг бүгдийг өгнө
   (хариунд гинж ирдэггүй). certificatePolicies-ийг шалгахгүй (CA-ийн гинжинд policyConstraints алга).
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
5. Цуцлалт — `TrustConfig.Revocation` (OCSP/CRL hook, `RevocationHardFail` анхдагч) → `CheckRevocation`, эсвэл
   `CheckRevocationStatus` (`good` / `unchecked` (soft-fail) / `skipped` (hook алга) + алдаа). QUALIFIED
   non-repudiation-д RP тохируулна.
6. Нэмэлт (сонголттой): `AllowedIssuerSKIs: []string{eid.CitizenIssuingCASKI}` — зөвхөн иргэний Issuing CA (04)-ийн
   гэрчилгээ (ижил root-ийн доорх байгууллагын CA-г хаана); `CheckKeyUsage: true` — auth → clientAuth, sign →
   nonRepudiation (CA-ийн профайл); `SchemeName` — CA-ийн `acsp_scheme_name` (анхдагч `smart-id`).

Аль нэг алхам бүтэлгүйтвэл `*eid.ValidationError` — хариунд **итгэхгүй**. Алдааны текстэд иргэний нэр, PNOMN, РД
ордоггүй (гэрчилгээг serial-аар, замыг `/etsi/…`-ээр) — шууд лог руу бичиж болно.

## 5. Алдааны төрлүүд (`errors.As`)

| Алдаа | Утга |
|---|---|
| `*eid.AuthenticationError` | 401 — API secret буруу/байхгүй; CA-ийн JSON бол `.Code`/`.Message`, proxy-ийнх бол хоосон (`.Body`, `.Header`) |
| `*eid.ForbiddenError` | 403 — IP allowlist / mTLS / RP-ийн эрх; `OnBehalfOf` татгалзвал `.Code` |
| `eid.ErrNoSigningCertificate` / `ErrCertChoiceInvalid` / `ErrRequestInvalid` | `errors.Is` — `*eid.APIError`-ийн `Code` (409 `NO_SIGNING_CERTIFICATE`, 409 `CERT_CHOICE_INVALID`, 400 `REQUEST_INVALID`) |
| `*eid.APIError` | бусад HTTP алдаа (`.Status`, `.Body`, `.Code`, `.RetryAfter`, `.Header`, `.Retryable()` — ж: 404 `ORG_NOT_FOUND`) |
| `*eid.ResponseTooLargeError` | хариу SDK-ийн хязгаараас их (JSON 4 MiB, PDF `Config.PDFMaxBytes`) — `.Op`, `.Limit` |
| `*eid.NetworkError` | сүлжээ / timeout (`.Timeout`, `Unwrap` → `context.DeadlineExceeded` г.м.); `.Op`-д иргэний дугаар `…` болно |
| `*eid.SessionFailedError` | endResult ≠ OK (`TIMEOUT`, `USER_REFUSED…`) — `.EndResult` |
| `*eid.ValidationError` | гинж / гарын үсэг / түвшин / урсгалын шалгалт унасан |
| `*eid.DeviceLinkError` | device link угсрах боломжгүй (оролтын хэлбэр) |

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

## 7. Клиент талын PAdES (`pades`)

PDF **eID-ийн аль ч серверт очихгүй** (Smart-ID + DigiDoc загвар): CA зөвхөн 32 байт hash (DTBS) зурна, PDF-ийн бүх
ажлыг (баталгаажуулалтын QR хуудас, placeholder, signedAttrs, CMS, RFC 3161, OCSP/CRL, DSS, өөрийн шалгалт) энэ сан
хийнэ. Профайл `pades-client/1` нь CA-ийн серверийн бичигчээс гаралтай (verify хуудас — шинэ минимал writer,
runtime-д шахалтгүй); ижил оролт → ижил байт.

```go
import "github.com/gerege-systems/eid-mongolia-sdk-go/pades"

p, err := pades.Prepare(pdfBytes, pades.PrepareOptions{
	SignerCert: certDER,          // certificate-choice session-ий cert.value (SIGN)
	VerifyPage: true,             // эхний eID гарын үсэгт л QR хуудас нэмэгдэнэ
	FileName:   "Гэрээ №12.pdf",
	ClaimedRole: rep.ClaimedRole, // байгууллагын нэрийн өмнөөс бол (төлөөллийн хариунаас), Reason: «<нэр>-ийг төлөөлж»
})
// p.DTBS → RAW_DIGEST_SIGNATURE session-ий digest (утас) эсвэл токены C_Sign; p.State-ийг хадгална (апп унтарч болно)
c, err := pades.Complete(ctx, p.State, signature, pades.CompleteOptions{}) // TSA https://tsa.timeserver.mn/, OCSP/CRL — AIA/CDP
if pades.ErrorCode(err) == pades.CodeTSAUnavailable { /* state хэвээр — дахин оролдоно */ }
// c.PDF — PAdES-BASELINE-LT. c.CMS, c.DocID, c.RevIndex, c.PriorCMSSHA256, c.SigRevSHA256, c.OutSHA256 … → CA-д бүртгэнэ
rep, err := pades.Verify(c.PDF, pades.VerifyOptions{}) // CA-ийн /v3/validate/pdf-тэй ижил тайлан, сүлжээгүй
```

- `signature`: RSA PKCS#1 v1.5, ECDSA `r‖s` (P-256 64 / P-384 96 байт) эсвэл DER — гэрчилгээний түлхүүрээр автоматаар.
- Итгэлийн тулгуур нь шигтгэсэн Mongolian National Root CA (01); 02–05 шигтгэсэн завсрын гинж (`Chain` өгөөгүй бол
  signer-ийн олгогчоор бүтээнэ). Тестийн PKI-д `CompleteOptions.Roots` / `VerifyOptions.Roots` (DER).
- Алдаа `*pades.Error` (`Code`): `PDF_INVALID`, `PDF_ENCRYPTED`, `PDF_LOCKED` (DocMDP P=1), `PDF_TOO_LARGE`
  (оролт > 10 223 616 байт), `PDF_TOO_MANY_SIGNATURES`, `PDF_PRIOR_SIGNATURE_INVALID`, `PDF_FOREIGN_SIGNATURE` (өмнөх
  гарын үсгийн signer нь eID-ийн 04/05-аас биш эсвэл SubFilter CAdES биш — [PRECHECKS.md](pades/PRECHECKS.md)), `SIGNER_INVALID`, `REQUEST_INVALID`, `SIGNATURE_INVALID`, `TSA_UNAVAILABLE`,
  `LTV_UNAVAILABLE`, `SELF_VALIDATION_FAILED`, `PLACEHOLDER_OVERFLOW`, `STATE_INVALID`.
- Гарын үсэгтэй баримтад дахин зурахад хуудас нэмэгдэхгүй; docID-г эхний хуудасны `/verify/<uuid>` холбоосоос уншина.

Go нь **reference хэрэгжүүлэлт** (бүрэн шалгагч `Verify`-тэй, backend-д); TS / Swift / Kotlin / C# native SDK-ууд гарын
үсгийн замыг ([PROFILE.md](pades/PROFILE.md), [PAGE_SPEC.md](pades/PAGE_SPEC.md), [PRECHECKS.md](pades/PRECHECKS.md),
[WIRE.md](pades/WIRE.md)) 1:1 давтаж, golden-ийг байт-ижил гаргана. Runtime-д шахалт хийхгүй (xref/DSS/хуудас) — хэл
хоорондын байт-ижил байдалд.

Golden vector: `pades/testdata/golden/` (README) — native SDK бүрийн CI тулгана.

## Хөгжүүлэлт

```bash
go vet ./... && go test -race ./...
go test ./pades -run Golden -update                                              # golden-ийг дахин бичих (профайл өөрчлөгдөхөд л)
```

Тест: CA серверийн device link golden векторууд (`testdata/devicelink_golden.json`, TS SDK-тэй ижил файл), Smart-ID
ACSP_V2 вектор, RFC 7636 PKCE вектор, бодит нийтийн CA гэрчилгээнүүд.

### Гэрээний шалгалт

SDK-ийн дууддаг RP-API зам бүр (`routes.go`) live [`/.well-known/eid`](https://rp.eidmongolia.mn/.well-known/eid)-ийн
`endpoints`-д байх ёстой. Discovery-д
байгаа ч SDK хамраагүй замууд WARN (fail биш). Сүлжээ шаарддаг тул энгийн `go test`-д ордоггүй:

```bash
go test -count=1 -v -tags contract -run Contract ./...
```

CI: `.github/workflows/contract.yml` — PR, `main` push, өдөр бүр 00:00 UTC, гараар.

---

## English

Go relying-party SDK for **eID Mongolia** — feature parity with the TypeScript SDK (Go ≥ 1.25; `eid`/`eidlogin` import the
standard library only).

- `eid.NewClient(eid.Config{…})` — RP-API v3: `Auth` (push / device link), `Sign` (raw digest), `PDF` (PAdES, CA-assembled,
  `OnBehalfOf`), `Organization`, `Session` (long-poll), `Validator`. Every call takes a `context.Context`.
- `Sign.DeviceLinkByEtsi` / `DeviceLinkByDocument` (sign via QR / Web2App / App2App; `DeviceLinkSession.LinkInput`),
  `Sign.CertificateChoiceByEtsi` / `CertificateChoiceDeviceLink` + `Validator.ValidateCertificateChoice` → `Signer`,
  `Sign.DigestForSigner` / `DeviceLinkForSigner` (sign on the chosen device's `documentNumber`; default
  `sha256WithRSAEncryption`), `ValidateSignOptions.ExpectedAlgorithm` / `ExpectedCertificate`, `ExpiresAt`
  from the CA's start response (`expiresAt`, RFC 3339; estimated via `Config.SignSessionTTL` on older CAs), and
  `errors.Is` sentinels `ErrNoSigningCertificate` / `ErrCertChoiceInvalid` / `ErrRequestInvalid`.
- `eid.BuildDeviceLink` — device link v3 (QR / Web2App / App2App) with HMAC `authCode`, byte-identical to the server
  golden vectors. Prefer **Web2App** for same-device sign-in; the legacy `/dl?sessionId&vc` link is gone.
- `Validator.ValidateAuth` / `ValidateSign` — certificate chain to the Mongolian National Root CA
  (`eid.NationalRootCAPEM`) via `x509.Certificate.Verify` (pathLen, keyCertSign, name constraints, EKU nesting —
  auth → clientAuth, sign → emailProtection — unknown critical extensions rejected), validity, level, ACSP_V2 / digest signature (RSA-PSS, PKCS#1 v1.5, ECDSA P-256/SHA-256), flow-type relay
  guard; `CheckRevocation` with your OCSP/CRL hook. Never trust `endResult == OK` alone.
- `eid.DocumentVerified` — downloaded PDF SHA-256 equals the session's `pdf.outSha256`. `Config.PDFMaxBytes` caps the
  in-memory PDF (default 64 MiB), JSON responses over 4 MiB fail with `*eid.ResponseTooLargeError` (never truncated).
  USB-token PAdES: `PDF.TokenPrepare` → token signs `HashToSign` (raw r||s) → `PDF.TokenFinalize` → `PDF.TokenDocument`. Transient CA errors
  (`PDF_PREPARE_BUSY`, `DOCUMENT_PENDING`, `TSA_UNAVAILABLE`, `LTV_UNAVAILABLE`) → `APIError.Retryable()` + `RetryAfter`.
- Show `RoleLabel` / `RightTypeLabel` / `SourceLabel` (representations; session `OnBehalfOf` has `RoleLabel` /
  `RightTypeLabel`), never translate `Role` / `RightType` / `Source` (machine values). `Config.Language` (`"mn"` | `"en"`) sends `Accept-Language`; unset = server default (mn).
- `SessionResult.Person` (CA person block, check with `PersonMatchesCertificate`) and `.Raw`; `Person` (PKI_READ:
  certificates, devices, activity, summary, children); `Token` (USB token certificate issuance and token sign-in).
- Error texts carry no personal identifiers (paths masked, certificates by serial) — safe to log.
- `eidlogin.New` — "Log in with eID" one-button backend (net/http, mount at `/auth/eid/`): `start` (QR / push by
  registration number / Web2App 302), `status` (fresh QR every second), `callback` (Web2App + `userChallengeVerifier`).
  State server-side (`Store`), browser bound by an HttpOnly cookie; identity only after `ValidateAuth`. Pairs with the
  TS SDK's `<eid-login-button>` web component. The OIDC client (`oidc` package) was removed in v0.2.0.
  `Identity` carries `SessionID`, `DocumentNumber` and `Certificate` for follow-up signing. Set `Config.ClientIP`
  (`ForwardedClientIP(n)` behind n trusted proxies, `RemoteAddrIP` otherwise) for the `start:<ip>` limit. Requires eID
  app iOS ≥ 2.2.3 (59) / Android ≥ 60 (server-enforced minimum is higher).
- `pades` — client-side PAdES baseline B-LT (the PDF never reaches eID servers; the CA signs only the 32-byte DTBS):
  `Prepare` (verification page, placeholder, signedAttrs → DTBS + opaque state) → `Complete` (signature check, RFC 3161,
  CMS, OCSP/CRL from AIA/CDP, DSS, self-validation with the CA's validator) → `Verify`. Derived from the CA writer
  (profile `pades-client/1`). It is the reference for the native TS/Swift/Kotlin/C# SDKs (PROFILE.md, PAGE_SPEC.md,
  PRECHECKS.md, WIRE.md; no runtime compression) — golden vectors in `pades/testdata/golden`.
- Typed errors via `errors.As`. RP registration: <eIDsupport@gerege.com>. Docs: <https://developer.eidmongolia.mn/#overview>.

License: MIT.
