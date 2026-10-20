# eid-mongolia-sdk-go

**eID Mongolia** relying-party SDK for Go — иргэнийг утсаар нь нэвтрүүлэх (authentication) ба хууль ёсны цахим гарын
үсэг (qualified signature) зуруулах, «eID-ээр нэвтрэх» товчны backend. RP-API v3, Smart-ID нийцтэй.
TypeScript хувилбартай ([gerege-systems/eid-mongolia-sdk](https://github.com/gerege-systems/eid-mongolia-sdk))
функциональ ижил. Бүрэн баримт: <https://developer.eidmongolia.mn/#overview>.

> SDK **backend**-д ажиллана: бүх дуудлага API secret (`rp_sk_…`)-ээр баталгаажна. Secret, `SessionSecret`-ийг
> браузер/гар утсанд хэзээ ч бүү гарга — браузерт зөвхөн таны backend-ийн өгсөн холбоос / QR / товч харагдана.

- Go ≥ 1.25. `eid`, `eidlogin` нь стандарт сан + `golang.org/x/crypto/ocsp` (OCSP цуцлалт) импортлодог; `pades` (PDF)
  нь digitorus/pdf, pkcs7, timestamp, `golang.org/x/crypto`, `golang.org/x/text`.
- Багц: `eid` (RP-API, device link, validator, PDF бүртгэл), `eidlogin` (`github.com/gerege-systems/eid-mongolia-sdk-go/eidlogin`
  — «eID-ээр нэвтрэх» товчны net/http handler),
  `pades` (клиент талын PAdES — PDF eID-ийн серверт очихгүй; native SDK-уудын reference).

[English summary](#english)

## Суулгах

```bash
go get github.com/gerege-systems/eid-mongolia-sdk-go@v0.13.0
```

```go
import (
	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
	"github.com/gerege-systems/eid-mongolia-sdk-go/eidlogin"
)
```

## 1. RP бүртгүүлэх

RP-г eID Mongolia-гийн оператор бүртгэнэ — хүсэлтээ <eIDsupport@gerege.com>-оор гаргана. Өргөдлийн API
(`POST https://ca.eidmongolia.mn/v3/rp-applications`, discovery-ийн `registration.apply`) одоогоор засвартай — 503
`rp_applications_maintenance` буцаана (2026-10-15 шалгасан). Баталсны дараа
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
| `GET /auth/eid/status` | cookie | `PENDING` (`vc`, `expiresIn`, +шинэ `qr`) · `WAIT_CALLBACK` · `OK` (`redirect`, `data`) · `FAILED` (`error`) · `EXPIRED` |
| `GET /auth/eid/callback` | апп буцаана: `?sessionId&userChallengeVerifier` | `303` → `Success.Redirect` / `SuccessRedirect`, алдаа бол `FailureRedirect?eid_error=<код>` |

eID сервер Web2App буцах замыг үргэлж `/auth/eid/callback` болгож нормчилдог тул `/auth/eid/` дор mount хийнэ:

```go
c, _ := eid.NewClient(eid.Config{
	Credentials: eid.Credentials{RPUUID: uuid, RPName: "Интернэт банк", APISecret: secret},
	// Root (01) — итгэлийн тулгуур; завсрын 02 → 03 → 04 нь SDK-д суусан (eid.CitizenIntermediatesPEM, анхдагч).
	Trust: eid.TrustConfig{TrustAnchorsPEM: []string{eid.NationalRootCAPEM}},
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
	// RateLimits: map[string]eidlogin.RateRule{"start": {Max: 20, Window: time.Minute}}, // анхдагчтай нэгтгэгдэнэ (push 3/мин хэвээр)
	OnEvent: func(ctx context.Context, kind eidlogin.EventKind, sessionID string, meta map[string]any) {
		audit.Record(ctx, "auth.eid_"+string(kind), sessionID, meta) // таны аудит
	},
	// AuditKey: []byte(os.Getenv("EID_AUDIT_KEY")), // pushKey-ийг instance/restart хооронд тогтвортой болгох
})
if err != nil {
	log.Fatal(err)
}
mux.Handle("/auth/eid/", login)
```

Хөтөчид:

```html
<script type="module" src="https://cdn.jsdelivr.net/npm/@gerege-systems/eid-mongolia-sdk@0.26.0/dist/button.js"></script>
<eid-login-button start-url="/auth/eid/start" status-url="/auth/eid/status" lang="mn"></eid-login-button>
```

Desktop дээр цонх (QR секунд тутам шинэчлэгдэнэ + регистрээр push), утсан дээр eID апп шууд нээгдэнэ. Амжилттай бол
`eid-login-success` үйл явдал ба `redirect` руу шилжилт. Өнгө: `--eid-*` (хуудасны аль ч түвшинд, light ба dark хоёуланд),
`--eid-<нэр>-dark` (зөвхөн dark-д давуу) — бүрэн жагсаалт TS SDK-ийн README §1a.

**Аюулгүй байдал.**

- `SessionToken`, `SessionSecret`, `rpChallenge` серверт (`Store`); хөтөчид зөвхөн HttpOnly, Secure, SameSite=Lax cookie
  (`<sessionId>.<binding>`, store-д SHA-256). Status ба callback зөвхөн нэвтрэлтийг **эхлүүлсэн хөтөчид** — өөр хөтчид нээгдсэн
  callback URL (verifier-тэй ч) хүлээн авагдахгүй (login CSRF).
- `start` POST нь JSON заавал (cross-origin preflight), `Sec-Fetch-Site: cross-site` → 403.
- `OK` нь зөвхөн `Validator.ValidateAuth` амжилттай үед: QR → `FlowQR`, push → `FlowNotification`, утас → `FlowWeb2App` +
  `userChallengeVerifier`. Web2App session-ийг poll дуусгахгүй (`WAIT_CALLBACK`). `OnSuccess` нэг session-д нэг л удаа
  (`Store.Delete` атомар — Redis `DEL`).
- `Success.Data` хөтөчид очно — нууц бүү оруул.
- **Регистрийн oracle хаалт (decoy + доод хугацаа, анхдагчаар асаалттай).** eID push-ийг дугаарын шалтгаанаар татгалзвал
  (eID-ийн өөрийн JSON 4xx — танихгүй / ашиглах боломжгүй дугаар) handler бодит push-тэй **ижил** хариу өгнө: `{mode, vc
  (санамсаргүй 5 оронтой — eID-тэй ижил хэлбэр), expiresIn}`, ижил cookie; `status` нь eID-ээс асуулгүй `Poll`-ын хугацаанд
  барьж `PENDING`, TTL-ийн дараа `EXPIRED` — утсаа аваагүй иргэнтэй ялгаагүй (бодит push-ийн CA `TIMEOUT` ч `EXPIRED` болно). Push start-ийн хариу бүр (бодит, decoy, 502)
  `PushFloor`-оос (анхдагч 1 с) хурдан гарахгүй — decoy-г цагаар ялгахгүйн тулд. Хязгаар (`push:<idCode>`, `start:<ip>`)
  decoy-д ч үйлчилнэ; 429 ба 400 (`invalid_id` — хэлбэрийн алдаа, бүртгэлээс хамааралгүй) нь floor-гүй.
  eID-ийн 5xx, холболтын алдаа, JSON бус 4xx (eID-ийн өмнөх proxy, ж: mTLS татгалзал), 401/403 (RP-ийн нууц/эрх) ба 429 нь
  **decoy биш** — `502 eid_unavailable` / `429` (eID порталын зан: тасалдлыг decoy-оор нуувал иргэн дуусахгүй spinner харна;
  эдгээр нь дугаараас хамаардаггүй тул oracle биш). Унтраах: `DisableDecoy`, `DisablePushFloor` — **АНХААР:** тэгвэл
  `/start` нь «энэ регистр eID-д бүртгэлтэй эсэх»-ийг нэвтрээгүй хэнд ч хэлнэ; зөвхөн дотоод/тестийн орчинд.
- **Хугацаа (`Config.TTL`, анхдагч 2 мин) CA-ийн session-оос урт байхгүй.** QR / Web2App: `expiresIn`, cookie
  `Max-Age`, store = min(`TTL`, CA-ийн start хариуны `expiresAt` − одоо). Push (бодит ба decoy **ижил**): min(`TTL`,
  discovery `sessionTtl.auth`) — decoy-д CA хариу байхгүй тул CA-ийн `expiresAt`-аас бус discovery-оос (`c.Auth.SessionTTL`,
  handler дотор 10 мин кэш, татаж чадаагүй бол 1 мин-ийн дараа дахин) — хугацааны зөрүү oracle болохгүй. Хуучин CA
  (discovery-д `sessionTtl` алга): бодит push-ийн `expiresAt`-аас ажигласан утгыг дараагийн decoy авна (±1 с); анхны
  бодит push-ээс өмнө `TTL`.
- **Гэрчилгээний цуцлалт (OCSP, анхдагчаар асаалттай).** `ValidateAuth`-ийн дараа, `OnSuccess`-ийн өмнө иргэний гэрчилгээг
  түүний AIA-д бичигдсэн OCSP responder-оос асууна (`Config.Revocation`, nil = `eid.NewOCSPChecker`; хариу олгогч эсвэл
  түүний OCSPSigning responder-ийн гарын үсэгтэй, энэ serial-ийн, thisUpdate ≤ 48 цаг, good-ийг min(5 мин, NextUpdate) кэшлэнэ).
  `revoked`, мөн `unknown` (олгогч энэ гэрчилгээг олгоогүй) → `FAILED` / `VALIDATION` (500 биш), `OnSuccess` дуудагдахгүй.
  Хариугүй (timeout 2 с, 5xx, AIA алга, шалгалт унасан хариу): `RevocationMode` "" = soft-fail — зөвшөөрч Warn лог,
  `Identity.Revocation = unchecked` (eID порталын `EID_OCSP=soft`: CA-ийн responder унавал бүх иргэн түгжигдэхгүй; утас
  session-ийг батлахад CA секундын өмнө хүрэх боломжтой байсан); `eid.RevocationHardFail` → `FAILED` / `VALIDATION`.
  `DisableRevocation` — **АНХААР:** цуцалсан (хулгайлагдсан утасны) гэрчилгээгээр нэвтэрнэ.
- **Аудит — `Config.OnEvent(ctx, kind, sessionID, meta)`** (синхрон): `push_sent` (meta `decoy` — зөвхөн таны аудитад,
  хөтөч рүү хэзээ ч), `push_limited`, `refused` (иргэн татгалзсан), `expired` (TIMEOUT / eID-д олдохгүй), `unverified`
  (`reason`: `validation` | `revoked` | `revocation_unavailable`), `flow_refused` (Web2App callback өөр хөтчид), `success`
  (`flow`, `revocation`), `failed` (бусад `endResult`). meta-д `mode`; токен/нууц, регистрийн дугаар орохгүй — push-д
  `pushKey` = HMAC-SHA256(`AuditKey`, дугаар)-ын 32 hex (`AuditKey` nil бол процесс бүрт санамсаргүй).
- `OnSuccess`-ээс ӨМНӨ tx store-оос атомар устгагдана (нэг удаагийн баталгаа) — `OnSuccess` дотор store-оос бүү унш;
  хэрэгтэй бүхэн `Identity`-д (`SessionID`, `DocumentNumber`, `Certificate`, …).

**Клиент IP** (`start:<ip>` хязгаар) — `Config.ClientIP`. Итгэмжит reverse proxy-ийн ард `eidlogin.ForwardedClientIP(n)`:
`X-Forwarded-For`-ийн **баруунаас n** дахь утга (n = таны proxy-ийн тоо), XFF байхгүй бол `X-Real-IP`, hop дутвал `""`.
Proxy-гүй бол `eidlogin.RemoteAddrIP`. nil бол IP-ээр хязгаарлахгүй (`New` нэг удаа Warn бичнэ). TS SDK-ийн
`trustProxy` / `getClientIp`-тэй ижил дүрэм.

**Хязгаарлалт.** Түлхүүр: `start:<ip>` (ClientIP өгсөн бол), `push:<idCode>`; татгалзвал 429 + `Retry-After: 60`.
Анхдагч `eidlogin.DefaultRateLimit()` = `{"start": {Max: 20, Window: time.Minute}, "push": {Max: 3, Window: time.Minute}}`
— нэг IP-ээс минутад 20 эхлэл (v0.6.0-аас; `ClientIP` өгсөн бол), нэг дугаарт минутад 3 мэдэгдэл (MFA fatigue). Санах
ойн хязгаарлагч төрөл тус бүрд ≤ 10 000 түлхүүр: дүүрвэл цонх нь өнгөрсөнийг цэвэрлэж, хоосроогүй бол **шинэ** түлхүүрийг
429-өөр татгалзана (fail-closed) — байгаа тоолуурыг хэзээ ч арилгахгүй тул олон IP/дугаараар дүүргэж хязгаарыг тойрох
боломжгүй. `NewMemoryStore()` ч мөн адил ≤ `eidlogin.MemoryStoreMax` (10 000): дүүрвэл start 503 `{"error":"busy"}`
(`eidlogin.ErrStoreFull`), эхэлсэн нэвтрэлтийг устгахгүй. Олон instance бол Redis store/limiter.

- `Config.RateLimits map[string]RateRule` — анхдагчтай **нэгтгэгдэнэ**: өгсөн төрөл (`"start"` | `"push"`) анхдагчийг
  дарна, өгөөгүй нь анхдагчаараа. `RateRule{Max, Window}` — процессын санах ойн гулсах цонх; `RateRule{Func: …}` — өөрийн
  (Redis г.м.); `RateRule{}` — тухайн төрлийг хязгаарлахгүй. Өөр түлхүүр → `New` алдаа.
- `Config.RateLimit func(ctx, key) bool` — бүх түлхүүрт, анхдагч хязгаар **дээр нэмэгдэнэ** (хоёулаа зөвшөөрөх ёстой).
  Анхдагчийг сулруулах/солих бол `RateLimits`-ээр тухайн төрлийг өг.

```go
lim := eidlogin.DefaultRateLimit()                                  // илэрхий бичих бол
lim["start"] = eidlogin.RateRule{Func: redisAllow}                  // push 3/мин хэвээр
// lim["start"] = eidlogin.RateRule{}                               // start-ийг nginx/gateway-д хязгаарладаг бол
lim["push"] = eidlogin.RateRule{Func: redisAllowPush}               // олон instance: push-ийг Redis-ээр солино
cfg.RateLimits = lim
```

TS SDK-ийн `rateLimit` (`{ start?, push? }` | функц, `defaultRateLimit`) — ижил утга.

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
шинэчлүүлдэг: Android 2026-10-07-оос ≥ 70, 2026-10-20-ны байдлаар iOS ≥ 2.2.8, Android ≥ 91
(`curl https://ca.eidmongolia.mn/mobile/app-config`). Иймд гарын үсэг зурж чадах бүх апп эдгээрийг дэмжинэ. Эх сурвалж:
eID CA-ийн `docs/DEVICE_LINK_V3.md` §5, §7; changelog `2026-10-02-ios-min-version-2-2-3`, `2026-10-07-android-min-70`.

## 3. RP-API client

```go
c, err := eid.NewClient(eid.Config{
	// BaseURL анхдагч https://rp.eidmongolia.mn (RP-API, /v3-гүй) — mTLS-тэй RP ч мөн энэ хост
	Credentials: eid.Credentials{
		RPUUID:    os.Getenv("EID_RP_UUID"),
		RPName:    "Интернэт банк", // дэд системийн нэр, ≤ 120 байт UTF-8 (кирилл ≈ 60 үсэг; CA илүүг таслана)
		APISecret: os.Getenv("EID_SECRET"),
	},
	Trust: eid.TrustConfig{
		TrustAnchorsPEM: []string{eid.NationalRootCAPEM}, // Mongolian National Root CA (01) — production-д ЗААВАЛ
		// IntermediatesPEM nil = eid.CitizenIntermediatesPEM (02 MDDC → 03 Gerege → 04 eID Mongolia Issuing CA)
	},
})
```

Бүх дуудлага `context.Context` авна (цуцлалт, deadline); дуудлага бүрийн анхдагч хугацаа `Config.Timeout` (15s),
long-poll өөрийн уртыг, `PDF.RegisterSignature` `Config.PDFTimeout`-ийг (анхдагч 80s — CA CMS + TSA + LTV-г шалгадаг;
TS SDK 0.19.0-аас `pdfTimeoutMs` ижил 80 с) хэрэглэнэ. Завсрын CA-уудын эх: <https://developer.eidmongolia.mn/#verification>.

### 3.1. Нэвтрэлт — push

```go
s, err := c.Auth.NotificationByEtsi(ctx, "PNOMN-12345678", // ETSI / регистр / иргэний дугаар (сервер танина)
	[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "Интернэт банкинд нэвтрэх"}}, nil)
show(s.VC) // 5 оронтой баталгаажуулах код — ПИН БИШ, зөвхөн харуулна

// long-poll; session-ий хугацаа (ExpiresAt + 15 с; nil бол discovery sessionTtl, эс бөгөөс 600 с) дуустал хүлээнэ.
// CA хугацаа дууссан session-ийг COMPLETE/TIMEOUT болгоно; MaxWait өгвөл түүгээр таслаж RUNNING-ийг алдаагүй буцаана.
r, err := c.Session.WaitForResult(ctx, s.SessionID, &eid.WaitOptions{ExpiresAt: s.ExpiresAt})
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
who, err = c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{
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
(`TIMEOUT`). CA-ийн тохиргооны амьд утга: `c.Auth.SessionTTL(ctx)` — discovery `sessionTtl` (`Auth`, `Sign`; хуучин CA-д 0).

**Session эхлэх алдаа** (`*eid.APIError`, `errors.Is`-ээр): `eid.ErrNoSigningCertificate` — 409 `NO_SIGNING_CERTIFICATE`
(sign / certificate-choice start: иргэнд идэвхтэй төхөөрөмж / хүчинтэй гарын үсгийн гэрчилгээ алга,
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

### 3.4. Байгууллагын нэрийн өмнөөс

Иргэн **өөрийн PIN2 гэрчилгээгээр** зурна; байгууллагыг төлөөлөх эрхийг eID өөрийн бүртгэлээр шалгана (хувь хүний
квалификацтай гарын үсэг — байгууллагын тамга биш). PDF-д гарын үсэг зурах нь клиент талын PAdES — [§7](#7-клиент-талын-pades-pades).

```go
reps, err := c.Organization.GetRepresentations(ctx, "PNOMN-12345678") // иргэн сүүлийн 24 цагт нэвтэрсэн байх
s, err := c.Sign.DigestForSigner(ctx, signer, dtbs, ix, &eid.SignOptions{OnBehalfOf: "NTRMN-6235972"})
// r.OnBehalfOf — СЕРВЕР төлөөллийг шалгасны баталгаа (nil = хувь хүн)
```

`OnBehalfOf` татгалзвал `*eid.ForbiddenError` / `*eid.APIError`-ийн `Code` (`eid.OnBehalfErrorCodes`):
`REPRESENTATION_DENIED`, `REPRESENTATION_PENDING`, `REPRESENTATION_EXPIRED`, `ORG_NOT_ACTIVE`, `SIGNER_UNIDENTIFIED`
(403) · `ORG_NOT_FOUND` (404) · `REPRESENTATION_REVOKED` (403, `RegisterSignature` ба токены гэрчилгээ олголтод).

Түр алдаа — `*eid.APIError.Retryable()` үнэн, `RetryAfter`-ийн (CA-ийн `Retry-After`, секунд эсвэл огноо) дараа
давтана (`eid.RetryableCodes`; кодгүй 429/503 + `Retry-After` ч мөн). `Header` — хариуны бүх header.

JSON хариу 4 MiB-ээс хэтэрвэл `*eid.ResponseTooLargeError` (таслахгүй). `GetRepresentations`-ийн `Raw` — серверийн
түүхий JSON.

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

`PersonCertificate`-д (v0.5.0-аас) `IssuedAt` (олгосон), `RevokedAt` (цуцалсан — REVOKED), `RevocationReason` (RFC 5280
нэр: `keyCompromise`, `superseded`, `cessationOfOperation` …). `Status` өөрчлөгдөхгүй: сунгалт/дахин бүртгэлээр солигдсон
мөр `SUSPENDED` + `RevocationReason: "superseded"`, `RevokedAt` nil.

`KeyMedium == "TOKEN"` мөрөнд `Organization` (байгууллагын токен, хувийнх nil) ба `TokenSerial` — гэрчилгээ олгогдсон
USB токены серийн дугаар. Нэг токены AUTH + SIGN-ийг байгууллага/огноогоор таамаглахгүй, `TokenSerial`-аар бүлэглэ
(сунгалтаар солигдсон мөр ч өөрийн токены дугаартай). MOBILE/HSM мөрөнд болон хуучин CA-д `""`.

### 3.7. USB токен

```go
// гэрчилгээ олголт (TOKEN_ISSUE эрх) — иргэн утсаараа PIN2-оор батална
in := eid.TokenCertInput{SignerEtsi: etsi, CSRAuth: csrA, CSRSign: csrS,
	TokenSerial: "EP2003-0042A1", OnBehalfOf: ""} // "" = хувийн токен
// push-ээс ӨМНӨ: ижил оролтоор dryRun — session/push үүсэхгүй, алдааны код бодиттой ижил
pv, err := c.Token.PreviewCertificate(ctx, in) // pv.Supersedes байвал иргэнд анхааруулж зөвшөөрүүлээд ↓
st, err := c.Token.IssueCertificate(ctx, in)
// st.Supersedes — хувийн олголтод солигдох өмнөх хувийн токенууд (доор); PIN2-оос өмнө иргэнд анхааруул
if l, ok := eid.TokenLimitOf(err); ok { /* 409 TOKEN_LIMIT_REACHED: l.Kind, l.Limit, l.Organization */ }
// 409 eid.CodeTokenInUse — serial өөр иргэнд; 409 eid.CodeTokenScopeChange — сунгалт scope солих гэсэн (доор)
// 400 eid.CodeAppAttestationInvalid — AppTransaction ирсэн боловч хүчингүй (доор)
// … c.Session.Poll → r.TokenCertificate.Status == eid.TokenCertIssued
res, err := c.Token.CertificateResult(ctx, st.SessionID)
err = eid.VerifyTokenCertificates(res, csrA, csrS) // гэрчилгээ бүр CSR-ийн түлхүүртэй

// токеноор нэвтрэх (AUTH эрх)
ch, err := c.Token.AuthChallenge(ctx)
digest, _ := eid.TokenAuthDigest(ch.RPUUID, ch.Challenge) // токен CKM_ECDSA → түүхий r||s
// v0.6.0-аас challenge-ийг бүтнээр нь (RP хадгалсан, эсвэл клиентээс буцаж ирсэн — CA ChallengeID-ээр тулгана):
// SDK CA-ийн OK-д дангаар итгэхгүй — r||s-ийг гэрчилгээний түлхүүрээр, RPUUID-ийг өөрийнхтэй, гэрчилгээг Trust-аар
// (гинж, issuer, зориулалт auth) шалгаад дараа нь CA руу илгээнэ.
who, err := c.Token.AuthVerify(ctx, ch, authCertDER, rs)

// токеноор PDF — клиент талын PAdES (§7): токен DTBS-ийг зурна, RegisterSignature-д Medium: eid.PDFMediumToken
```

**Сунгалт scope-ийг хадгална** (CA 2026-10-16, discovery `tokenCertificate.scopeLockedOnRenewal: true` —
`c.Token.CertificateInfo(ctx)`): ижил `TokenSerial` дээр иргэний ACTIVE бүртгэл байвал олголт = сунгалт; байгууллагын
токен зөвхөн тэр байгууллагаар (`OnBehalfOf` ижил), хувийн токен зөвхөн хувиараа. Өөр scope бол `IssueCertificate`
(эсвэл батлалтын дараа `CertificateResult`) 409 `eid.CodeTokenScopeChange` (`TOKEN_SCOPE_CHANGE`), session-ий
`TokenCertificate.ErrorCode` мөн ийм — override байхгүй. Scope солих = иргэн eID апп-аас токеноо цуцлаад
(`/v3/mobile/tokens/{tokenSerial}/revoke`) шинээр олгуулна; хэрэглэгчид: «Токены төрлийг (хувийн/байгууллага)
солихын тулд eID апп-аас токеныг цуцлаад шинээр олгуулна уу».

**Хувийн токены автомат солилт** (CA 2026-10-19, discovery `tokenCertificate.personalAutoSupersede: true`): хувийн
хязгаар хүрсэн үед өөр `TokenSerial`-тай шинэ хувийн токен 409 биш — `st.Supersedes` (`[]eid.TokenSupersede{TokenSerial}`)
ирнэ; хувийн токенд шинэ олголт амжилттай болбол (PIN2 + гэрчилгээ) өмнөх хувийн токены AUTH + SIGN superseded (4)-оор
цуцлагдана. Татгалзсан / хугацаа дууссан олголт өмнөхийг хөндөхгүй. PIN2-оос өмнө: «Таны өмнөх USB токен (EP2003-…)-ийн
гэрчилгээ хүчингүй болно». 409 `TOKEN_LIMIT_REACHED` `kind=PERSONAL` зөвхөн `limit=0` (хувийн олголт хаалттай) үед;
байгууллагын токен (`ORGANIZATION`) хатуу хязгаар хэвээр.

**dryRun — push-ээс өмнөх шалгалт** (CA 2026-10-19, discovery `tokenCertificate.dryRun: true` —
`CertificateInfo().DryRun`): `IssueCertificate`-ийн хариунд `Supersedes` ирэх үед утас руу PIN2 push явсан байдаг —
desktop дээр цуцалсан ч иргэн утсаараа баталбал хуучин токен солигдоно. Тиймээс урсгал: CSR → `c.Token.PreviewCertificate(ctx, in)`
(бие нь ижил + `"dryRun": true`; бүх шалгалт, ижил алдааны код — өөр CSR хостой хүлээгдэж буй олголт
`409 TOKEN_ISSUANCE_PENDING` ч; session / push / state үүсэхгүй) → `Supersedes` байвал анхааруулга, иргэн зөвшөөрөх →
`IssueCertificate(ctx, in)`. Хурдны хязгаар (RP, иргэн) 20/мин ба RP нийт 120/10 мин — push-ийн 3/цагийг зарцуулахгүй. Хариунд `dryRun: true` ирээгүй бол `*eid.ValidationError` (хуучин CA танихгүй талбарт 400 буцаана).

**Апп баталгаа (`AppTransaction`, заавал биш)** (CA 2026-10-19, discovery `tokenCertificate.appTransaction:
"optional"`): macOS App Store build нь StoreKit 2 `AppTransaction`-ийн JWS (compact) мөрийг desktop-оос дамжуулна —
`eid.TokenCertInput{…, AppTransaction: jws}`. CA Apple-ийн сервер рүү дуудахгүй, offline шалгана; ирсэн бол заавал
хүчинтэй, эс бөгөөс 400 `eid.CodeAppAttestationInvalid` (`APP_ATTESTATION_INVALID`, аль алхам унасныг хэлэхгүй, утас
руу push явахгүй). `""` (Windows) = баталгаагүй олголт. `eid.MaxAppTransactionBytes` (16 KiB)-аас их бол SDK илгээхгүй,
`eid.ErrAppTransactionTooLarge` буцаана. Хуучин CA-д (`CertificateInfo().AppTransaction == ""`) талбар илгээвэл 400.

`/token/auth/*` нь `/.well-known/eid`-ийн `endpoints.token.auth_challenge` / `auth_verify`-д жагсаагдсан (AUTH эрх) —
гэрээний тест бусад route-ийн адил шалгана.

### 3.8. Гарын үсэгтэй файлыг имэйлээр — `c.Share` (`SIGN` эрх)

Гарын үсэг зурсан PDF-ээ дараагийн гарын үсэг зурагч / хүлээн авагч руу хавсралтаар илгээнэ (`POST /share`). CA файлыг
**хадгалахгүй**: eID-ийн хүчинтэй гарын үсэгтэй эсэхийг шалгаад илгээж, хаяна. Хүлээн авагч бүрт тусдаа имэйл.

> CA дээр үргэлж асаалттай (2026-10-16-наас туг байхгүй). Хязгаар, квотыг `c.ShareInfo(ctx)`-ээс уншина;
> `Enabled` false бол имэйлийн үйлчилгээ түр тохируулагдаагүй (503).

```go
info, err := c.ShareInfo(ctx) // Enabled, MaxFileBytes, MaxRecipients, Quota{PerRPHour, PerRPDay, PerRecipientDay}, …
if err == nil && info.Enabled {
	res, err := c.Share(ctx, eid.ShareRequest{
		File:     signedPDF,                // ≤ 3 080 192 байт, eID-ийн хүчинтэй гарын үсэгтэй PDF
		Filename: "гэрээ.pdf",              // .pdf өргөтгөлтэй; "" = document.pdf
		To:       []string{"next@example.mn"}, // 1–5, давхардалгүй
		Subject:  "Гэрээ — гарын үсэг",      // ≤ 150; CA «‹RP нэр›: …» угтвар тавина
		Message:  "Хоёр дахь гарын үсгийг зурна уу", // ≤ 1000
		Lang:     "mn",                      // mn | en
	})
	var se *eid.ShareError
	switch {
	case errors.As(err, &se) && se.Code == eid.CodeMailFailed:
		// se.Recipients[i] == eid.ShareRecipientFailed — зөвхөн тэднийг дахин илгээ
	case errors.As(err, &se) && se.Code == eid.CodeFileNotSigned:
		// se.Reason: eid.ShareReasonNoSignature | ShareReasonInvalid | ShareReasonUntrusted
	case err == nil:
		_ = res.DocID // CA-д бүртгэлтэй бол (имэйлд verify холбоос)
	}
}
```

| HTTP | `ShareError.Code` | Тайлбар |
|---|---|---|
| 400 | `REQUEST_INVALID`, `FILE_EMPTY`, `RECIPIENT_REQUIRED`, `TOO_MANY_RECIPIENTS`, `RECIPIENT_INVALID`, `RECIPIENT_DUPLICATE` | талбарын алдаа |
| 413 | `FILE_TOO_LARGE` | файл / имэйл хязгаараас их |
| 415 | `FILE_TYPE_NOT_SUPPORTED` | PDF биш (өргөтгөл, Content-Type, `%PDF-` гурвуулаа таарна) |
| 422 | `FILE_NOT_SIGNED` | `.Reason`: `no_signature` \| `invalid` \| `untrusted` |
| 429 | `RATE_LIMITED` | квот; `.RetryAfter`, `.Retryable()` |
| 502 | `MAIL_FAILED` | `.Sent`, `.Failed`, `.Recipients` (`To`-гийн дарааллаар `sent` \| `failed`) |
| 503 | `MAIL_UNAVAILABLE`, `VALIDATOR_UNAVAILABLE`, `VALIDATOR_BUSY` (`SHARE_DISABLED` — хуучин CA) | тохиргоо / ачаалал (`VALIDATOR_*` — Retry-After) |

401 → `*eid.AuthenticationError`, 403 (SIGN эрхгүй, IP/mTLS) → `*eid.ForbiddenError`. Квот: RP тутам цагт 300 / өдөрт 3000
хүсэлт, хүлээн авагч тутам өдөрт 10 имэйл (бодит утгыг `ShareInfo().Quota`-аас). Хугацаа `DefaultShareTimeout` (150 с);
ctx-ийн deadline богино бол тэр нь ялна.

## 4. Аюулгүй байдал — яагаад `Validator` заавал

`EndResult == "OK"` гэдэгт **дангаар нь итгэхгүй** — RP-API эвдэрсэн/proxy хийгдсэн бол хуурамч OK ирж болзошгүй.
`Validator` (<https://developer.eidmongolia.mn/#verification>):

1. `State == COMPLETE` (эс бөгөөс `*ValidationError` — ж: `WaitForResult`-ийн RUNNING) ба `EndResult == OK` (эс бөгөөс
   `*SessionFailedError`).
2. Иргэний гэрчилгээг **trust anchor (Mongolian National Root CA, `eid.NationalRootCAPEM`)** хүртэл гинжээр
   (Root 01 → National Issuing CA 02 → Gerege Issuing CA 03 → eID Mongolia Issuing CA 04 → иргэн) — Go-ийн
   `x509.Certificate.Verify` (RFC 5280): CA basicConstraints + **pathLenConstraint** (04 нь `pathlen:0`), CA-ийн
   keyUsage keyCertSign, **name constraints**, **EKU** (auth → clientAuth, sign → emailProtection — CA-ийн профайл;
   завсрын CA-д EKU байвал түүнд багтах), үл таних **critical extension** → татгалзана, гарын үсэг, хугацаа (гинжийг
   leaf-ийн хүчинтэй хугацаанд, `ClockSkew`-ийн хүрээнд). Trust anchor тохируулаагүй бол **fail-closed**
   (`AllowUntrusted` зөвхөн dev/тест). OS-ийн trust store-д итгэхгүй. Хариунд гинж ирдэггүй — `IntermediatesPEM` nil
   бол SDK-д суусан 02, 03, 04 (`eid.CitizenIntermediatesPEM`, v0.6.0-аас). certificatePolicies-ийг шалгахгүй
   (CA-ийн гинжинд policyConstraints алга).
3. Гэрчилгээ хүчинтэй хугацаанд (`ClockSkew`) + шаардсан түвшин (`RequiredLevel`, анхдагч `QUALIFIED`; `QSCD` хангана).
   **v0.6.0-аас түвшинг гэрчилгээнээс тогтооно** (`eid.CertificateLevelOf`): гарын үсгийн гэрчилгээнд qcStatements
   QcCompliance → QUALIFIED (+ QcSSCD → QSCD), qcStatements-гүй (USB токен) → ADVANCED; нэвтрэлтийн гэрчилгээнд CA
   qcStatements бичдэггүй тул профайлаар — KeyUsage keyEncipherment (утасны P-CITIZEN-AUTH) → QUALIFIED, үгүй (токены)
   → ADVANCED. Хариуны `CertificateLevel` түүнээс өндөр бол татгалзана; бага бол хариуныхыг авна.
   `VerifiedIdentity` / `VerifiedSignature` / `Signer`-ийн `CertificateLevel` = энэ утга.
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
   non-repudiation-д RP тохируулна. Бэлэн hook: `eid.NewOCSPChecker(eid.OCSPOptions{})` — гэрчилгээний AIA OCSP
   (revoked/unknown → revoked; хариугүй → unknown, горим шийднэ). Өөр checker/горимоор нэг удаа: `CheckRevocationWith`.
   `OCSPOptions` (v0.5.2+): `CacheTTL` (good-ийн кэш = min(CacheTTL, NextUpdate−одоо); анхдагч 5 мин, сөрөг = кэшгүй);
   `Observe func(eid.OCSPObservation)` — шалгалт бүрд (кэшээс ч) `Status`, `Responder` URL, `Duration`, `Cached`, `Err`
   (PII-гүй) — метрик/аудитад. Хариугүй бол checker `RevocationUnknown` + `*eid.OCSPError` (`Kind`: `no_responder`,
   `no_issuer`, `timeout`, `network`, `http_status` (+`HTTPStatus`), `responder_status`, `parse`, `signature`, `invalid`;
   `errors.Is(err, eid.ErrOCSPNoAnswer)`) буцаана; `CheckRevocationWith` үүнийг unknown гэж горимоор шийднэ — soft →
   `unchecked`, nil (шалтгааныг `Observe`-оос); hard → `*ValidationError` (`Cause` = `*OCSPError`). Олгогчийн гаргасан,
   хариунд шигтгэсэн `id-kp-OCSPSigning` responder (RFC 6960 §4.2.2.2, ocsp.eidmongolia.mn-ийн «eID OCSP Responder»)-ийг
   хүлээн авна (бодит хариугаар тест: `testdata/ocsp-eid-delegated.der`); олгогч өөрөө зурж, өөрийн гэрчилгээг
   шигтгэсэн хариуг ч (v0.6.0-аас; RFC 6960 §4.2.2.2) issuer-ийн түлхүүрээр шалгаж хүлээн авна.
6. **Issuer ба зориулалт (v0.6.0-аас анхдагч):** `AllowedIssuerSKIs` хоосон бол `[]string{eid.CitizenIssuingCASKI}`
   (TrustAnchorsPEM тохируулсан үед) — зөвхөн иргэний Issuing CA (04)-ийн гэрчилгээ (ижил root-ийн доорх байгууллагын
   05 г.м. хаагдана; унтраах: `AllowAnyIssuer: true`); зориулалт анхдагчаар шалгагдана — auth → KU digitalSignature +
   EKU clientAuth, sign → KU nonRepudiation (CA-ийн профайл): нэвтрэлтийн (PIN1) түлхүүрийн гарын үсэг `ValidateSign`-д
   тэнцэхгүй (унтраах: `SkipKeyUsageCheck: true`, зөвлөхгүй; `CheckKeyUsage` deprecated, нөлөөгүй). `SchemeName` —
   CA-ийн `acsp_scheme_name` (анхдагч `smart-id`).

Аль нэг алхам бүтэлгүйтвэл `*eid.ValidationError` — хариунд **итгэхгүй**. Алдааны текстэд иргэний нэр, PNOMN, РД
ордоггүй (гэрчилгээг serial-аар, замыг `/etsi/…`-ээр) — шууд лог руу бичиж болно.

## 5. Алдааны төрлүүд (`errors.As`)

| Алдаа | Утга |
|---|---|
| `*eid.AuthenticationError` | 401 — API secret буруу/байхгүй; CA-ийн JSON бол `.Code`/`.Message`, proxy-ийнх бол хоосон (`.Body`, `.Header`) |
| `*eid.ForbiddenError` | 403 — IP allowlist / mTLS / RP-ийн эрх; `OnBehalfOf` татгалзвал `.Code` |
| `eid.ErrNoSigningCertificate` / `ErrCertChoiceInvalid` / `ErrRequestInvalid` | `errors.Is` — `*eid.APIError`-ийн `Code` (409 `NO_SIGNING_CERTIFICATE`, 409 `CERT_CHOICE_INVALID`, 400 `REQUEST_INVALID`) |
| `*eid.ShareError` | `Share`-ийн 4xx/5xx (401/403-аас бусад) — `.Code`, `.Reason` (422), `.Sent`/`.Failed`/`.Recipients` (502); `Unwrap` → `*eid.APIError` |
| `*eid.APIError` | бусад HTTP алдаа (`.Status`, `.Body`, `.Code`, `.RetryAfter`, `.Header`, `.Retryable()` — ж: 404 `ORG_NOT_FOUND`) |
| `*eid.ResponseTooLargeError` | хариу SDK-ийн хязгаараас их (JSON 4 MiB) — `.Op`, `.Limit` |
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

// 1. Гэрчилгээ (certificate-choice) — signedAttrs-ийн signingCertificateV2-д hash-аас ӨМНӨ хэрэгтэй.
cc, err := c.Sign.CertificateChoiceByEtsi(ctx, "PNOMN-12345678", nil)
r, err := c.Session.WaitForResult(ctx, cc.SessionID, nil)
signer, err := c.Validator.ValidateCertificateChoice(r, cc.SessionID)
// 2. (байгууллагын нэрийн өмнөөс бол) CA-ийн тооцоолсон мэдүүлсэн үүрэг — өөрчлөхгүй дамжуулна.
reps, err := c.Organization.GetRepresentations(ctx, "PNOMN-12345678")
claimedRole := reps.Representations[0].ClaimedRole // OrgEtsi == onBehalfOf-той мөр
// 3. Prepare — PDF таны серверт үлдэнэ; эхний eID гарын үсэгт QR хуудас (mn, Lang: "en").
p, err := pades.Prepare(pdfBytes, pades.PrepareOptions{SignerCert: signer.Certificate.Raw, VerifyPage: true,
	FileName: "Гэрээ №12.pdf", ClaimedRole: claimedRole, Reason: "Тест ХХК-ийг төлөөлж"})
// 4. DTBS-ийг ЯГ ТЭР төхөөрөмжөөр зуруулна. DigestForSigner / DeviceLinkForSigner-ийн анхдагч алгоритм =
//    sha256WithRSAEncryption (PKCS#1 v1.5) — CMS-д заавал (DigestByEtsi-ийн анхдагч rsassa-pss-ийг Complete
//    REQUEST_INVALID-аар татгалзана).
s, err := c.Sign.DigestForSigner(ctx, signer, base64.StdEncoding.EncodeToString(p.DTBS), interactions,
	&eid.SignOptions{OnBehalfOf: "NTRMN-6235972"})
res, err := c.Session.WaitForResult(ctx, s.SessionID, nil)
_, err = c.Validator.ValidateSign(res, s.Sign.Digest, s.Sign.HashAlgorithm, eid.ValidateSignOptions{
	ExpectedAlgorithm: s.Sign.SignatureAlgorithm, ExpectedCertificate: signer.Certificate, ExpectedFlowType: eid.FlowNotification})
sig, _ := base64.StdEncoding.DecodeString(res.SignatureValueB64)
// 5. Complete — TSA https://tsa.timeserver.mn/, OCSP/CRL (AIA/CDP), DSS, өөрийн шалгалт.
done, err := pades.Complete(ctx, p.State, sig, pades.CompleteOptions{})
// OCSP/CRL түр унавал SDK өөрөө 2 удаа дахин оролдоно (~1с, ~3с + jitter; PIN дахин асуухгүй) — CompleteOptions.LTVRetries.
if pades.ErrorCode(err) == pades.CodeTSAUnavailable { /* p.State хэвээр — дахин оролдоно */ }
// 6. CA-ийн бүртгэл (docID, /verify) — заавал. Medium "" бол SessionID-аас (phone ⇔ sessionID); ClaimedRole-той
// гарын үсэгт OnBehalfOf-гүй бол REQUEST_INVALID (CA-д очихоос өмнө).
reg, err := pades.Registration(done, pades.RegistrationOptions{Medium: eid.PDFMediumPhone, SessionID: s.SessionID,
	OnBehalfOf: "NTRMN-6235972"})
_, err = c.PDF.RegisterSignature(ctx, reg) // POST /pdf/signatures
// done.PDF — PAdES-BASELINE-LT
rep, err := pades.ValidatePDF(ctx, done.PDF, pades.ValidateOptions{}) // CA-ийн /v3/validate/pdf-тэй ижил тайлан (§7.2)
```

Бүтэн, compile-оор шалгагддаг хувилбар: `pades/example_test.go` (`Example`).

- `signature`: RSA PKCS#1 v1.5, ECDSA `r‖s` (P-256 64 / P-384 96 байт) эсвэл DER — гэрчилгээний түлхүүрээр автоматаар;
  RSASSA-PSS → `SIGNATURE_INVALID` («PKCS#1 v1.5 шаардлагатай»; TS / .NET / Swift / Kotlin-той ижил код).
- `RegisterSignature` — `POST /pdf/signatures`, бие нь CA-ийн `PDFSignatureRegisterRequest`-тэй яг ижил (`hasPage`
  илгээхгүй; `signerEtsi` = гэрчилгээний SERIALNUMBER). Эхний гарын үсэг бүртгэгдэхийн тулд verify хуудастай байна.
  `Created` — `true` 201 (шинэ), `false` 200 (ижил биеийн давталт). Өмнөх гарын үсэг CA-ийн угсарсан (горим A) бол
  `Registration`-ийн `PriorSignatures` (CMS + `sha256(doc[0 : ByteRange[2]+ByteRange[3]])` хос) -оор 409
  `PRIOR_MISMATCH`-ийн дараа SDK өөрөө revision-оор тааруулна (`PriorRevisionSHA256`-г гараар тавибал оролдохгүй).
- Итгэлийн тулгуур нь шигтгэсэн Mongolian National Root CA (01); 02–05 шигтгэсэн завсрын гинж (`Chain` өгөөгүй бол
  signer-ийн олгогчоор бүтээнэ). Тестийн PKI-д `CompleteOptions.Roots` / `VerifyOptions.Roots` (DER).
- Алдаа `*pades.Error` (`Code`): `PDF_INVALID`, `PDF_ENCRYPTED`, `PDF_LOCKED` (DocMDP P=1), `PDF_TOO_LARGE`
  (оролт > 10 223 616 байт), `PDF_TOO_MANY_SIGNATURES`, `PDF_PRIOR_SIGNATURE_INVALID`, `PDF_FOREIGN_SIGNATURE` (өмнөх
  гарын үсгийн signer нь eID-ийн 04/05-аас биш эсвэл SubFilter CAdES биш — [PRECHECKS.md](pades/PRECHECKS.md)), `SIGNER_INVALID`, `REQUEST_INVALID`, `SIGNATURE_INVALID`, `TSA_UNAVAILABLE`,
  `LTV_UNAVAILABLE`, `SELF_VALIDATION_FAILED`, `PLACEHOLDER_OVERFLOW`, `STATE_INVALID`.
- **LTV retry (v0.6.0)** — OCSP/CRL (DSS) цуглуулалт унавал (`LTV_UNAVAILABLE` нөхцөл, ж: үндэсний CRL толь түр 404)
  `Complete` ижил state, гарын үсэг, TSA timestamp-аар өөрөө дахин оролдоно: `CompleteOptions.LTVRetries` (`*int`; nil =
  `pades.DefaultLTVRetries` 2 — нийт 3 оролдлого, хүлээлт ~1 с, ~3 с + 0–25% jitter; `0` — унтраах; 0–10-аас гадуур →
  `REQUEST_INVALID`). Бүгд унавал `LTV_UNAVAILABLE`; `ctx` цуцлагдвал хүлээлт тасарч `context.Canceled`-ийг боосон
  `LTV_UNAVAILABLE`. TS SDK 0.18.3-ийн `ltvRetries`-тэй ижил — TS ба Go хоёулаа LTV retry-тэй.
- Гарын үсэгтэй баримтад дахин зурахад хуудас нэмэгдэхгүй; docID-г эхний хуудасны `/verify/<uuid>` холбоосоос уншина.

### 7.1. Харагдах гарын үсэг (сонголттой)

Анхдагч нь үл харагдах (өмнөхтэй байт-ижил). RP хуудсан дээр тэгш өнцөгт өгвөл widget нь нэр, (onBehalfOf бол) үүрэг,
«eID Mongolia-аар зурсан» / «Signed with eID Mongolia», `YYYY-MM-DD HH:MM (+08)` огноо, гарын үсэг тус бүрийн QR
(`https://ca.eidmongolia.mn/verify/<docID>/<revIndex>`)-тэй дүрслэл зурна:

```go
p, err := pades.Prepare(pdfBytes, pades.PrepareOptions{SignerCert: cert, VerifyPage: true, FileName: "Гэрээ.pdf",
	Appearance: &pades.Appearance{Page: 0, X: 36, Y: 36, Width: 220, Height: 64}}) // Page 0 = оролтын eID verify хуудас БИШ сүүлийн хуудас
```

- Координат — pt, хуудасны CropBox (байхгүй бол MediaBox)-ийн **дэлгэцэнд харагдах** (`/Rotate`-ийн дараах) зүүн доод
  булангаас; `/Rotate` 0/90/180/270 бүгд дэмжигдэнэ (дүрслэл босоо харагдана). 0.01 pt хүртэл тойрно.
- `Page` нь Prepare-д өгсөн баримтын хуудас (1-ээс; тодорхой дугаар юуг ч алгасахгүй). 0 = eID verify хуудас БИШ сүүлийн
  хуудас — энэ Prepare-ийн нэмэх ба өмнөх revision-уудын нэмсэн verify хуудас тооцогдохгүй (v0.12.0+, PLACEMENT_SPEC §1a).
- `X, Y` нь хүссэн байрлал: тэр хэсэгт хуудасны агуулга (бичвэр, хүснэгтийн зураас, зураг, өмнөх гарын үсэг) байвал
  дүрслэл чөлөөт зай руу шилжинэ — эхлээд толин тусгал багана (баруун доод → зүүн доод), дараа нь 12 pt-ээр дээш.
  Үр дүн: `Prepared.Placement` (`Status`: `requested` | `moved` | `overlap` — чөлөөт зай алга, хүссэн байрлалд
  | `unscanned` — хуудсыг хязгаарт багтааж уншиж чадсангүй). Дэлгэрэнгүй: [PLACEMENT_SPEC.md](pades/PLACEMENT_SPEC.md).
- Өндөр ≥ 45 pt (QR модуль ≥ 1 pt), бичвэр багтахгүй (нэр 7 pt, бусад 5 pt хүртэл жижгэрнэ), хуудаснаас гарсан, хуудас
  алга, `/Name` бичигдэхгүй нэр, docID тодорхойгүй → `REQUEST_INVALID`. Огноо нь мэдүүлсэн SigningTime (TSA-ийн цаг prepare-д
  мэдэгдэхгүй).
- `Verify` тайлан: `visible` (энэ гарын үсэг харагдах), `visible_later_signature`. Шалгагч зөвхөн яг энэ хэлбэрийг (widget +
  `/AP`-ийг дахин үүсгэж байт-түвшинд тулгана) хүлээн авна. Дэлгэрэнгүй: [APPEARANCE_SPEC.md](pades/APPEARANCE_SPEC.md).

### 7.2. Гарын үсэгтэй PDF шалгах — `pades.ValidatePDF` (v0.7.0)

RP өөрийн backend дээр (файлыг хаашаа ч илгээлгүй) CA-ийн нийтийн шалгагчийн (`/v3/validate/pdf`) кодоор шалгана —
тайлан нь CA-ийн JSON-той ижил (snake_case). Хөтөчид ижил дүрэм: TS SDK `validatePdf` (`@gerege-systems/eid-mongolia-sdk/validate`).

```go
rep, err := pades.ValidatePDF(ctx, pdfBytes, pades.ValidateOptions{}) // анхдагч: шигтгэсэн үндэсний Root CA, онлайн цуцлалт
switch pades.ErrorCode(err) {
case pades.CodePDFNoSignature, pades.CodePDFInvalid, pades.CodePDFTooLarge, pades.CodePDFTooManySignatures: // 4xx
case pades.CodePDFEncrypted: // v0.7.1: шифрлэгдсэн (/Encrypt) — нууцлалыг арилгаад дахин илгээхийг хэрэглэгчид хэл
case pades.CodeRequestInvalid: // ValidateOptions.Roots/Intermediates/Issuers задрахгүй
}
if rep.Indication == pades.Valid { /* бүх гарын үсэг хүчинтэй */ }
for _, s := range rep.Signatures {
	_ = s.SignerName           // гэрчилгээнээс (claimed_name — PDF-д бичигдсэн, баталгаагүй)
	_ = s.SigningTime          // итгэмжлэгдсэн RFC 3161 цаг
	_ = s.SignatureLevel       // PAdES-BASELINE-B | -T | -LT
	_ = s.CertificateLevel     // QUALIFIED | QSCD | ADVANCED (qcStatements)
	_ = s.Problems             // integrity_failed, untrusted_chain, revoked, modified_after_signing …
}
```

- Шалгалт: ByteRange (завсар нь яг энэ `/Contents`) ба messageDigest, CMS гарын үсэг, signingCertificateV2, гинж
  (үндэсний 01 → 02/03 → 04/05), KU/EKU (иргэний SIGN, байгууллагын тамга, doc-signer; AUTH/TLS → `wrong_key_usage`),
  хугацаа (цагийн тэмдгийн цагт), RFC 3161 токен (TSA гинж, critical timeStamping EKU), гарын үсгийн ДАРААХ revision бүр зөвхөн
  eID-ийн гарын үсэг/LTV-ийн зөвшөөрөгдсөн хэлбэр (бусад → `modified_after_signing`), харагдах гарын үсэг (APPEARANCE_SPEC
  §5), LTV-ийн бүрэн байдал (`ltv`).
- Цуцлалт (eID-ийн 04/05-аас гарсан гэрчилгээнд): онлайн — AIA OCSP, эс бөгөөс CDP CRL (олгогчийн гарын үсэгтэй); хариугүй
  эсвэл `Offline: true` бол баримтын DSS. Аль нь ч үгүй → `revocation_unavailable` (indeterminate). Цагийн тэмдгээс хойш
  цуцлагдсан → `revoked_after_signing` (хүчинтэй хэвээр). Сүлжээгээр зөвхөн гэрчилгээний serial (OCSP) явна, баримт биш.
- Цуцлалтын нотолгооны дүрэм (v0.7.2): OCSP нь ЭНЭ гэрчилгээнийх (CertID = гинжийн олгогчийн нэр/түлхүүрийн hash +
  serial), CRL нь олгогчийнх (нэр, AKI, гарын үсэг). «good» нь шалгах цагт шинэлэг байх ёстой: thisUpdate ирээдүйд биш
  (5 мин хүлцэл), nextUpdate өнгөрөөгүй, thisUpdate ≤ 24 цагийн өмнө эсвэл thisUpdate…nextUpdate нь шалгах цагийг хамарна
  (шалгах цаг = итгэмжлэгдсэн цагийн тэмдгийн цаг, эс бөгөөс `Time`/одоо). Эс бөгөөс тооцохгүй → `revocation_unavailable`.
  Олгогчийн гарын үсэгтэй «revoked» нотолгоо (OCSP эсвэл CRL, онлайн эсвэл DSS) нь «good»-ийг үргэлж давна.
- **Итгэлгүй PDF.** `Prepare`/`ValidatePDF`/`Verify`/`Complete` задлахын өмнө массив/толийн давхарлалтыг
  (`> 256` → `Prepare`/`ValidatePDF`/`Verify`-д `PDF_INVALID`, `Complete`-д `STATE_INVALID`; аль алинд
  `errors.Is(err, pades.ErrPDFStructure)`) шалгадаг (v0.7.2; өмнө нь ~2 MB `[[[…` баримт
  `fatal error: stack overflow`-оор процессыг бүхэлд нь унагадаг байв). Энэ нь хамгаалалтын нэг давхарга л — гаднаас ирсэн
  PDF-ийг итгэлгүй оролт гэж үзэж хэмжээг хязгаарла (≤ 10 MiB), хүсэлт бүрд timeout тавь, боломжтой бол тусдаа
  процесс/контейнерт (CPU/санах ойн хязгаартай) задал.
- `key_medium`: SDK гэрчилгээнээс л — qcStatements-тэй иргэний SIGN → `phone`, бусад `unknown` (CA бүртгэлээсээ `token` ч
  тогтооно). `session_id`, `doc_id`, `on_behalf_of_*`, `stamp_lookup` нь CA-ийн бүртгэлээс — SDK-д байхгүй.
- Шифрлэгдсэн PDF (`/Encrypt` — RC4, AES-128, AES-256, хоосон хэрэглэгчийн нууц үгтэй ч) → `PDF_ENCRYPTED` (v0.7.1;
  өмнө нь `PDF_INVALID`, RC4-д зөв гарын үсгийг `malformed_signature` гэж буруу хүчингүйд тооцдог байв). TS SDK, CA ижил.
- `Verify` (v0.5) = `ValidatePDF` + `Offline: true` (deprecated; гарын үсэггүй баримтад хуучин зангаар хоосон `valid`).
- Conformance: `pades/testdata/validate/` — Go, TS ба CA ижил багцаар ижил тайлан.

Go нь **reference хэрэгжүүлэлт** (бүрэн шалгагч `Verify`-тэй, backend-д); TS / Swift / Kotlin / C# native SDK-ууд гарын
үсгийн замыг ([PROFILE.md](pades/PROFILE.md), [PAGE_SPEC.md](pades/PAGE_SPEC.md), [PRECHECKS.md](pades/PRECHECKS.md),
[WIRE.md](pades/WIRE.md), [APPEARANCE_SPEC.md](pades/APPEARANCE_SPEC.md), [PLACEMENT_SPEC.md](pades/PLACEMENT_SPEC.md)) 1:1 давтаж, golden-ийг байт-ижил гаргана. Runtime-д шахалт хийхгүй (xref/DSS/хуудас) — хэл
хоорондын байт-ижил байдалд.

Golden vector: `pades/testdata/golden/` (README, tag `pades-golden-v6`) — native SDK бүрийн CI тулгана; энэ репогийн CI
гаралт бүрийг qpdf (`--check`) ба pyHanko-оор (INTACT/VALID/TRUSTED, DSS-ээс LT, харагдах эсэх) бие даан шалгана.

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
standard library plus `golang.org/x/crypto/ocsp`; `pades` also digitorus pdf/pkcs7/timestamp and `golang.org/x/text`).

- `eid.NewClient(eid.Config{…})` — RP-API v3: `Auth` (push / device link), `Sign` (raw digest, `OnBehalfOf`), `PDF`
  (`RegisterSignature` for client-side PAdES), `Organization`, `Session` (long-poll), `Validator`. Every call takes a `context.Context`.
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
- JSON responses over 4 MiB fail with `*eid.ResponseTooLargeError` (never truncated). Transient CA errors
  (`eid.RetryableCodes`, or 429/503 with `Retry-After`) → `APIError.Retryable()` + `RetryAfter`. The upload-based PDF
  client (`PDF.Prepare` / `Document` / `Token*`, `DocumentVerified`) was removed in v0.4.0 — use `pades`.
- Show `RoleLabel` / `RightTypeLabel` / `SourceLabel` (representations; session `OnBehalfOf` has `RoleLabel` /
  `RightTypeLabel`), never translate `Role` / `RightType` / `Source` (machine values). `Config.Language` (`"mn"` | `"en"`) sends `Accept-Language`; unset = server default (mn).
- `SessionResult.Person` (CA person block, check with `PersonMatchesCertificate`) and `.Raw`; `Person` (PKI_READ:
  certificates, devices, activity, summary, children); `Token` (USB token certificate issuance and token sign-in).
- `Client.Share` (SIGN, v0.5.0) — e-mail a signed PDF (valid eID signature required; the CA does not store it) to 1–5
  recipients; `*eid.ShareError` (`Code`, `Reason` on 422, `Sent`/`Failed`/`Recipients` on 502 `MAIL_FAILED`).
  `Client.ShareInfo` reads the discovery `share` block (limits, quota; the CA has no share flag since 2026-10-16).
  `PersonCertificate` gained `IssuedAt`, `RevokedAt`, `RevocationReason` (RFC 5280 name).
- Error texts carry no personal identifiers (paths masked, certificates by serial) — safe to log.
- `eidlogin.New` — "Log in with eID" one-button backend (net/http, mount at `/auth/eid/`): `start` (QR / push by
  registration number / Web2App 302), `status` (fresh QR every second), `callback` (Web2App + `userChallengeVerifier`).
  State server-side (`Store`), browser bound by an HttpOnly cookie; identity only after `ValidateAuth`. Pairs with the
  TS SDK's `<eid-login-button>` web component. The OIDC client (`oidc` package) was removed in v0.2.0.
  `Identity` carries `SessionID`, `DocumentNumber` and `Certificate` for follow-up signing. Set `Config.ClientIP`
  (`ForwardedClientIP(n)` behind n trusted proxies, `RemoteAddrIP` otherwise) for the `start:<ip>` limit. On by default:
  a push the CA refuses for the number (its own JSON 4xx) is answered with a decoy session identical to a real unanswered
  push (no registration oracle), every push start takes at least `PushFloor` (1 s), the certificate is checked over OCSP
  (`eid.NewOCSPChecker`, soft-fail when the responder does not answer, revoked/unknown → `FAILED`/`VALIDATION`), and
  `OnEvent` receives audit events. Opt-outs: `DisableDecoy`, `DisablePushFloor`, `DisableRevocation` (not recommended). Requires eID
  app iOS ≥ 2.2.3 (59) / Android ≥ 60 (server-enforced minimum is higher).
- `pades` — client-side PAdES baseline B-LT (the PDF never reaches eID servers; the CA signs only the 32-byte DTBS):
  `Prepare` (verification page, placeholder, signedAttrs → DTBS + opaque state) → `Complete` (signature check, RFC 3161,
  CMS, OCSP/CRL from AIA/CDP, DSS, self-validation with the CA's validator) → `ValidatePDF` (the CA's public validator
  — same JSON report as `/v3/validate/pdf`, online OCSP/CRL with DSS fallback, `certificate_level`). Derived from the CA writer
  (profile `pades-client/1`). It is the reference for the native TS/Swift/Kotlin/C# SDKs (PROFILE.md, PAGE_SPEC.md,
  PRECHECKS.md, WIRE.md; no runtime compression) — golden vectors in `pades/testdata/golden`.
  Revocation evidence (v0.7.2) counts only if it is for this certificate and its chain issuer (OCSP CertID, CRL issuer/AKI/
  signature) and fresh at the validation time (timestamp time, else now; ±5 min skew, 24 h max age unless the
  thisUpdate…nextUpdate window covers it); a signed "revoked" always wins. PDFs nested deeper than 256 levels are
  rejected (`PDF_INVALID`, `ErrPDFStructure`) before parsing — still treat untrusted PDFs as hostile input (size limit,
  timeouts, ideally an isolated process).
- Typed errors via `errors.As`. RP registration: <eIDsupport@gerege.com>. Docs: <https://developer.eidmongolia.mn/#overview>.

License: MIT.
