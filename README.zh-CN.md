[Монгол](README.md) · [English](README.en.md) · 中文

# eid-mongolia-sdk-go

**eID Mongolia** 的 Go 语言 relying-party SDK——让公民通过手机完成身份认证（authentication）并进行具有法律效力的电子
签名（qualified signature），同时也是“使用 eID 登录”按钮的后端。RP-API v3，兼容 Smart-ID。
与 TypeScript 版本（[gerege-systems/eid-mongolia-sdk](https://github.com/gerege-systems/eid-mongolia-sdk)）功能一致。
完整文档：<https://developer.eidmongolia.mn/#overview>。

> SDK 运行在**后端**：所有调用都通过 API secret（`rp_sk_…`）认证。绝不要将 secret 和 `SessionSecret`
> 暴露给浏览器/手机——浏览器只会看到您的后端提供的链接 / QR / 按钮。

- Go ≥ 1.25。`eid`、`eidlogin` 导入标准库 + `golang.org/x/crypto/ocsp`（OCSP 吊销检查）；`pades`（PDF）
  使用 `github.com/gerege-systems/pdf`（digitorus/pdf v0.1.2 的 fork，修复了 DoS 问题）、digitorus pkcs7、timestamp、
  `golang.org/x/crypto`、`golang.org/x/text`。
- 包：`eid`（RP-API、device link、validator、PDF 登记）、`eidlogin`（`github.com/gerege-systems/eid-mongolia-sdk-go/eidlogin`
  ——“使用 eID 登录”按钮的 net/http handler）、
  `pades`（客户端 PAdES——PDF 不会发送到 eID 服务器；是各 native SDK 的 reference）。

## 安装

```bash
go get github.com/gerege-systems/eid-mongolia-sdk-go@v0.31.0
```

`pades` 直接导入已打补丁的 PDF 解析器（`github.com/gerege-systems/pdf`），因此不需要 `replace`。
v0.21.x 及以前 README 中的 `replace github.com/digitorus/pdf => github.com/craftzbay/pdf …` 一行，SDK 已不再需要
（自 v0.22.0 起 SDK 不再导入 `github.com/digitorus/pdf`）——请删除。但如果您自己的代码导入了 `github.com/digitorus/pdf`
或 `github.com/digitorus/pdfsign`，为让它们保持已打补丁的状态，请保留该行。

```go
import (
	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
	"github.com/gerege-systems/eid-mongolia-sdk-go/eidlogin"
)
```

## 1. 注册 RP

RP 由 eID Mongolia 运营方注册——请将申请发送至 <eIDsupport@gerege.com>。申请 API
（`POST https://ca.eidmongolia.mn/v3/rp-applications`，discovery 的 `registration.apply`）目前处于维护状态——返回 503
`rp_applications_maintenance`（2026-10-15 检查）。批准后会分配
**relyingPartyUUID** 和 **API secret**（`rp_sk_…`）；secret **只显示一次**。所需
信息（组织、用途 `AUTH`/`SIGN`、`callbackHosts`……）：
<https://developer.eidmongolia.mn/#registration>。

## 2. “使用 eID 登录”——一个按钮（`eidlogin`）

Smart-ID RP 的常见模式：浏览器中**一个按钮**，所有 eID 调用都在您的后端完成（使用 API secret）。
`eidlogin.Handler`（net/http）是仅使用 §3.1/§3.2 的 RP-API（device link v3、push、`Validator`）的现成流程；
浏览器端按钮是 TS SDK 的 Web Component `<eid-login-button>`（`@gerege-systems/eid-mongolia-sdk/button`）——响应
格式与 TS 的 `createEidLogin` 相同。

| | 请求 | 响应 |
|---|---|---|
| `POST /auth/eid/start` | `{"mode":"qr"}` 或 `{"mode":"push","idCode":"УБ12345678"}`（必须是 JSON） | `{mode, vc, qr?, expiresIn}` + `Set-Cookie: __Host-eid_login` |
| `GET /auth/eid/start?mode=web2app` | 手机浏览器（按钮跳转） | `302` → eID 应用（Web2App） |
| `GET /auth/eid/status` | cookie | `PENDING`（`vc`、`expiresIn`，+新的 `qr`）· `WAIT_CALLBACK` · `OK`（`redirect`、`data`）· `FAILED`（`error`）· `EXPIRED` |
| `GET /auth/eid/callback` | 应用返回：`?sessionId&userChallengeVerifier` | `303` → `Success.Redirect` / `SuccessRedirect`，出错则为 `FailureRedirect?eid_error=<代码>` |

eID 服务器始终将 Web2App 的返回路径规范化为 `/auth/eid/callback`，因此请挂载在 `/auth/eid/` 下：

```go
c, _ := eid.NewClient(eid.Config{
	Credentials: eid.Credentials{RPUUID: uuid, RPName: "网上银行", APISecret: secret},
	// Root (01) 是信任锚；中间证书 02 → 03 → 04 已内置于 SDK（eid.CitizenIntermediatesPEM，默认）。
	Trust: eid.TrustConfig{TrustAnchorsPEM: []string{eid.NationalRootCAPEM}},
})
login, err := eidlogin.New(eidlogin.Config{
	Client:      c,
	CallbackURL: "https://bank.example.mn/auth/eid/callback", // host 必须在 callbackHosts 中；手机流程必须提供
	OnSuccess: func(w http.ResponseWriter, r *http.Request, id *eidlogin.Identity) (*eidlogin.Success, error) {
		// id.ETSI (PNOMN-…) —— 请据此识别用户；id.GivenName/Surname（拉丁文），id.Person（西里尔文，如有）
		// id.SessionID, id.DocumentNumber, id.Certificate —— 用于后续步骤（签名、关联证书）
		u, err := users.FindOrCreateByETSI(r.Context(), id.ETSI)
		if err != nil {
			return nil, err
		}
		sid, err := sessions.Create(r.Context(), u.ID) // 新建 session（防 session fixation）
		if err != nil {
			return nil, err
		}
		http.SetCookie(w, &http.Cookie{Name: "app_session", Value: sid, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		return &eidlogin.Success{Redirect: "/dashboard"}, nil
	},
	ClientIP: eidlogin.ForwardedClientIP(1), // 位于一跳 nginx/LB 之后；没有代理时使用 eidlogin.RemoteAddrIP
	// Store: redisStore,        // 多实例时使用（默认——进程内存）
	// RateLimits: map[string]eidlogin.RateRule{"start": {Max: 20, Window: time.Minute}}, // 与默认值合并（push 仍为 3/分钟）
	OnEvent: func(ctx context.Context, kind eidlogin.EventKind, sessionID string, meta map[string]any) {
		audit.Record(ctx, "auth.eid_"+string(kind), sessionID, meta) // 您的审计
	},
	// AuditKey: []byte(os.Getenv("EID_AUDIT_KEY")), // 使 pushKey 在多个实例/重启之间保持稳定
})
if err != nil {
	log.Fatal(err)
}
mux.Handle("/auth/eid/", login)
```

在浏览器中：

```html
<script type="module" src="https://cdn.jsdelivr.net/npm/@gerege-systems/eid-mongolia-sdk@0.26.0/dist/button.js"></script>
<eid-login-button start-url="/auth/eid/start" status-url="/auth/eid/status" lang="mn"></eid-login-button>
```

桌面端弹出窗口（QR 每秒刷新 + 通过注册号 push）；手机上则直接打开 eID 应用。成功后触发
`eid-login-success` 事件并跳转到 `redirect`。颜色：`--eid-*`（可设置在页面任意层级，对 light 和 dark 同时生效），
`--eid-<名称>-dark`（仅对 dark 优先生效）——完整列表见 TS SDK README 的 §1a。

**安全性。**

- `SessionToken`、`SessionSecret`、`rpChallenge` 保留在服务器（`Store`）中；浏览器只拿到 HttpOnly、Secure、SameSite=Lax 的 cookie
  （`<sessionId>.<binding>`，store 中为 SHA-256）。Status 和 callback 只响应**发起登录的那个浏览器**——在其他浏览器中打开的
  callback URL（即使带有 verifier）也不会被接受（登录 CSRF）。
- `start` 的 POST 必须是 JSON（跨域会触发 preflight），`Sec-Fetch-Site: cross-site` → 403。
- 只有 `Validator.ValidateAuth` 成功时才返回 `OK`：QR → `FlowQR`，push → `FlowNotification`，手机 → `FlowWeb2App` +
  `userChallengeVerifier`。Web2App 的 session 不会被 poll 结束（`WAIT_CALLBACK`）。`OnSuccess` 对每个 session 只执行一次
  （`Store.Delete` 必须是原子的——Redis `DEL`）。
- `Success.Data` 会发送到浏览器——不要放入机密。
- **注册号 oracle 防护（decoy + 最短耗时，默认开启）。** 当 eID 因号码原因拒绝 push 时
  （eID 自身的 JSON 4xx——未知 / 无法使用的号码），handler 返回与真实 push **完全相同**的响应：`{mode, vc
  （随机 5 位数字——与 eID 形式相同）, expiresIn}`、相同的 cookie；`status` 在 `Poll` 时间内不询问 eID，保持
  `PENDING`，TTL 后为 `EXPIRED`——与没有接手机的公民无法区分（真实 push 的 CA `TIMEOUT` 也会变为 `EXPIRED`）。每个 push start 的响应（真实、decoy、502）
  都不会快于 `PushFloor`（默认 1 s）——使 decoy 无法通过时间区分。限制（`push:<pushKey>`、`start:<ip>`）
  同样适用于 decoy；429 和 400（`invalid_id`——格式错误，与注册情况无关）没有 floor。
  eID 的 5xx、连接错误、非 JSON 的 4xx（eID 前面的 proxy，如 mTLS 拒绝）、401/403（RP 的 secret/权限）和 429 **不使用
  decoy**——返回 `502 eid_unavailable` / `429`（eID 门户的行为：若用 decoy 掩盖故障，公民会看到无尽的转圈；
  这些与号码无关，因此不构成 oracle）。关闭方式：`DisableDecoy`、`DisablePushFloor`——**注意：** 关闭后
  `/start` 会向任何未登录的人透露“该注册号是否已在 eID 注册”；仅限内部/测试环境。
- **有效期（`Config.TTL`，默认 2 分钟）不会超过 CA 的 session。** QR / Web2App：`expiresIn`、cookie
  `Max-Age`、store = min(`TTL`, CA start 响应的 `expiresAt` − 当前时间)。Push（真实与 decoy **相同**）：min(`TTL`,
  discovery `sessionTtl.auth`)——decoy 没有 CA 响应，所以取自 discovery（`c.Auth.SessionTTL`，
  handler 内缓存 10 分钟，获取失败则 1 分钟后重试）而非 CA 的 `expiresAt`——以免时长差异成为 oracle。旧版 CA
  （discovery 中没有 `sessionTtl`）：下一个 decoy 采用从真实 push 的 `expiresAt` 观察到的值（±1 s）；在首个
  真实 push 之前使用 `TTL`。
- **证书吊销（OCSP，默认开启）。** 在 `ValidateAuth` 之后、`OnSuccess` 之前，会向公民证书
  AIA 中列出的 OCSP responder 查询（`Config.Revocation`，nil = `eid.NewOCSPChecker`；响应须由颁发者或
  其 OCSPSigning responder 签名、针对该序列号、thisUpdate ≤ 48 小时，good 结果缓存 min(5 分钟, NextUpdate)）。
  `revoked`，以及 `unknown`（颁发者未签发此证书）→ `FAILED` / `VALIDATION`（不是 500），不会调用 `OnSuccess`。
  无响应（超时 2 s、5xx、没有 AIA、检查失败）时：`RevocationMode` 为 "" = soft-fail——放行并写 Warn 日志，
  `Identity.Revocation = unchecked`（eID 门户的 `EID_OCSP=soft`：CA 的 responder 宕机时不会锁住所有公民；而且手机
  确认 session 时 CA 可能提前几秒就已知情）；`eid.RevocationHardFail` → `FAILED` / `VALIDATION`。
  `DisableRevocation`——**注意：** 持有已吊销（被盗手机）证书的人也能登录。
- **审计——`Config.OnEvent(ctx, kind, sessionID, meta)`**（同步）：`push_sent`（meta `decoy`——仅出现在您的审计中，
  绝不发给浏览器）、`push_limited`、`refused`（公民拒绝）、`expired`（TIMEOUT / 在 eID 中找不到）、`unverified`
 （`reason`：`validation` | `revoked` | `revocation_unavailable`）、`flow_refused`（Web2App callback 出现在另一个浏览器）、`success`
 （`flow`、`revocation`）、`failed`（其他 `endResult`）。meta 中有 `mode`；不包含令牌/机密、注册号——对 push，
  `pushKey` = HMAC-SHA256(`AuditKey`, 号码) 的 32 位十六进制（若 `AuditKey` 为 nil，则每个进程随机生成）。
- 在调用 `OnSuccess` 之前，tx 已从 store 中原子删除（一次性保证）——不要在 `OnSuccess` 内部从 store 读取；
  所需的一切都在 `Identity` 中（`SessionID`、`DocumentNumber`、`Certificate`、……）。

**客户端 IP**（`start:<ip>` 限制）——`Config.ClientIP`。位于受信任的反向代理之后使用 `eidlogin.ForwardedClientIP(n)`：
取 `X-Forwarded-For` 中**从右数第 n 个**值（n = 您的代理数量），没有 XFF 则取 `X-Real-IP`，跳数不足则为 `""`。
没有代理时使用 `eidlogin.RemoteAddrIP`。若为 nil，则不按 IP 限制（`New` 会写一次 Warn）。规则与 TS SDK 的
`trustProxy` / `getClientIp` 相同。

**限流。** 键：`start:<ip>`（提供了 ClientIP 时；IPv6 取 `/64` 前缀，ClientIP 返回空则归入共享的 `start:unknown`）、`push:<pushKey>`（自 v0.32.0 起为审计 HMAC，而非号码）；被拒绝时返回 429 + `Retry-After: 60`。
默认 `eidlogin.DefaultRateLimit()` = `{"start": {Max: 20, Window: time.Minute}, "push": {Max: 3, Window: time.Minute}}`
——同一 IP 每分钟 20 次发起（自 v0.6.0 起；提供了 `ClientIP` 时），同一号码每分钟 3 条通知（防 MFA 疲劳攻击）。内存
限流器每种类型最多 ≤ 10 000 个键（`RateRule.MaxKeys`）：满了就清理已过期的窗口，若仍未腾出空间，则把**新**键计入同一个共享 overflow 桶（自 v0.32.0 起；此前为 429）——
绝不会清除已有计数器，因此无法通过塞满大量 IP/号码来绕过限制。
`NewMemoryStore()` 同样 ≤ `eidlogin.MemoryStoreMax`（10 000）：满了则 start 返回 503 `{"error":"busy"}`
（`eidlogin.ErrStoreFull`），不会删除已开始的登录。多实例时请使用 Redis store/limiter。

- `Config.RateLimits map[string]RateRule`——与默认值**合并**：您提供的类型（`"start"` | `"push"`）覆盖默认值，
  未提供的保持默认。`RateRule{Max, Window}`——进程内存中的滑动窗口；`RateRule{Func: …}`——您自己的
 （Redis 等）；`RateRule{}`——不限制该类型。其他键 → `New` 返回错误。
- `Config.RateLimit func(ctx, key) bool`——对所有键调用，**叠加在**默认限制之上（两者都必须放行）。
  若要放宽/替换默认值，请通过 `RateLimits` 指定该类型。

```go
lim := eidlogin.DefaultRateLimit()                                  // 若要显式写出
lim["start"] = eidlogin.RateRule{Func: redisAllow}                  // push 仍为 3/分钟
// lim["start"] = eidlogin.RateRule{}                               // 若在 nginx/gateway 中对 start 限流
lim["push"] = eidlogin.RateRule{Func: redisAllowPush}               // 多实例：用 Redis 替换 push
cfg.RateLimits = lim
```

TS SDK 的 `rateLimit`（`{ start?, push? }` | 函数，`defaultRateLimit`）——语义相同。

**Redis store**（SDK 没有额外依赖——例如 `github.com/redis/go-redis/v9`）：

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

// DEL 是原子的——两个并发的 status 调用中只有一个会触发 OnSuccess。
func (s redisStore) Delete(ctx context.Context, sid string) (bool, error) {
	n, err := s.rdb.Del(ctx, s.key(sid)).Result()
	return n == 1, err
}
```

Tx 中包含 `SessionSecret`（用于生成 QR 的材料）——请将 Redis 与外网隔离，并启用 TLS/AUTH。

**eID 应用的最低版本。** `flowType` 绑定（device link v3）和 Web2App 的 `userChallengeVerifier` 自
**iOS 2.2.3（build 59）**、**Android 2.2.3（versionCode 60）** 起支持。eID 服务器自 2026-10-07 起
完全移除了旧版链接（对没有 v3 的 session，手机返回 `DEVICE_LINK_REQUIRED`），并通过 `/mobile/app-config` 强制升级最低版本：
Android 自 2026-10-07 起 ≥ 70，截至 2026-10-20，iOS ≥ 2.2.8，Android ≥ 91
（`curl https://ca.eidmongolia.mn/mobile/app-config`）。因此所有能够签名的应用都支持这些。来源：
eID CA 的 `docs/DEVICE_LINK_V3.md` §5、§7；changelog `2026-10-02-ios-min-version-2-2-3`、`2026-10-07-android-min-70`。

## 3. RP-API client

```go
c, err := eid.NewClient(eid.Config{
	// BaseURL 默认为 https://rp.eidmongolia.mn（RP-API，不带 /v3）——使用 mTLS 的 RP 也用此主机
	Credentials: eid.Credentials{
		RPUUID:    os.Getenv("EID_RP_UUID"),
		RPName:    "网上银行", // 子系统名称，≤ 120 个字符（CA 会截断多余部分）
		APISecret: os.Getenv("EID_SECRET"),
	},
	Trust: eid.TrustConfig{
		TrustAnchorsPEM: []string{eid.NationalRootCAPEM}, // Mongolian National Root CA (01)——生产环境必须配置
		// IntermediatesPEM nil = eid.CitizenIntermediatesPEM (02 MDDC → 03 Gerege → 04 eID Mongolia Issuing CA)
	},
})
```

所有调用都接受 `context.Context`（取消、deadline）；每次调用的默认超时为 `Config.Timeout`（15s），
long-poll 使用自己的时长，`PDF.RegisterSignature` 使用 `Config.PDFTimeout`（默认 80s——CA 校验 CMS + TSA + LTV；
TS SDK 自 0.19.0 起的 `pdfTimeoutMs` 同为 80 s）。中间 CA 的来源：<https://developer.eidmongolia.mn/#verification>。

### 3.1. 认证——push

```go
s, err := c.Auth.NotificationByEtsi(ctx, "PNOMN-12345678", // ETSI / 注册号 / 公民编号（服务器会识别）
	[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "登录网上银行"}}, nil)
show(s.VC) // 5 位验证码——不是 PIN，仅用于显示

// long-poll；等待至 session 到期（ExpiresAt + 15 s；为 nil 时用 discovery 的 sessionTtl，否则 600 s）。
// CA 会将已过期的 session 置为 COMPLETE/TIMEOUT；若提供 MaxWait，则按其截止并返回 RUNNING（不报错）。
r, err := c.Session.WaitForResult(ctx, s.SessionID, &eid.WaitOptions{ExpiresAt: s.ExpiresAt})
who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{ExpectedFlowType: eid.FlowNotification})
if err != nil {
	return err // *eid.SessionFailedError (USER_REFUSED, TIMEOUT…) 或 *eid.ValidationError——不要信任
}
if err := c.Validator.CheckRevocation(ctx, who.Certificate); err != nil { // 若已配置 TrustConfig.Revocation
	return err
}
log.Println(who.DocumentNumber, who.Subject.SerialNumber, who.Subject.GivenName, who.Subject.Surname)
```

### 3.2. QR 与同设备——device link v3

公民用手机扫描另一块屏幕上的 **QR**，或者，如果 RP 的网站在与 eID 应用**同一部手机**上打开，则通过按钮
打开应用。**对于同一设备，请使用 Web2App（device link v3）流程**——在手机浏览器中点击按钮会直接
打开应用，确认之后带着 `userChallengeVerifier` 返回到您的 `CallbackURL`。（若来自 RP 的 native 应用，
则使用 App2App。）旧版 `/dl?sessionId&vc` 链接已于 2026-10-07 从服务器移除——SDK 中不存在。

```go
// 后端——发起 session，并将完整响应保存在服务器上 (SessionToken/SessionSecret/ReceivedAt/ACSP)
s, err := c.Auth.DeviceLinkAnonymous(ctx,
	[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "登录网上银行"}},
	&eid.AuthOptions{CallbackURL: "https://bank.example.mn/auth/eid/callback?tx=" + txID}) // 如需显示按钮；host = callbackHosts
store.Put(s.SessionID, s) // 只有 SessionID 和 VC 会发送给浏览器

link := func(s *eid.DeviceLinkSession, t eid.DeviceLinkType) (string, error) {
	return eid.BuildDeviceLink(eid.DeviceLinkInput{
		DeviceLinkBase: s.DeviceLinkBase, DeviceLinkType: t,
		SessionToken: s.SessionToken, SessionSecret: s.SessionSecret,
		SessionType: eid.SessionAuth, Lang: "mon", ReceivedAt: s.ReceivedAt,
		RPChallenge: s.ACSP.RPChallenge, RelyingPartyName: s.ACSP.RelyingPartyName,
		Interactions: s.ACSP.Interactions, InitialCallbackURL: s.ACSP.InitialCallbackURL, // 对 QR 而言不参与 authCode
	})
}

// GET /eid/qr?sessionId=… — 浏览器每秒调用一次并重新绘制 QR（QR 有效期约 20 秒）
http.HandleFunc("GET /eid/qr", func(w http.ResponseWriter, r *http.Request) {
	s := store.Get(r.URL.Query().Get("sessionId")) // 检查它是否属于调用者自己的浏览器 session
	l, err := link(s, eid.LinkQR)
	if err != nil {
		http.Error(w, "session 已结束", http.StatusGone)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"link": l})
})
// 手机端：按钮的 href = link(s, eid.LinkWeb2App)（只生成一次）
```

若通过 SSE/WebSocket 推送，请使用 `eid.TickQRDeviceLink(ctx, input, time.Second, send)`——立即发出一个链接，之后每秒一个；
通过取消 `ctx` 来停止。

**务必核对您所展示的类型（防中继）：**

```go
// QR 页面 → 通过轮询完成的结果
who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{ExpectedFlowType: eid.FlowQR})

// Web2App 按钮 → 收到 callback（?userChallengeVerifier=…）之后
who, err = c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{
	ExpectedFlowType:      eid.FlowWeb2App, // 若按钮位于 RP 的应用内，则为 eid.FlowApp2App
	UserChallengeVerifier: callback.Query().Get("userChallengeVerifier"),
})
```

在同时显示 QR 和按钮的同一页面上：使用同一个 session（带 `CallbackURL`），通过 callback 到达的结果按 `Web2App`/`App2App` 核对，
通过 poll 到达的结果按 `QR` 核对。

### 3.3. 签名（digest）

```go
digest := eid.SHA256Base64(docBytes)
s, err := c.Sign.DigestByEtsi(ctx, "PNOMN-12345678", digest,
	[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "签署贷款合同"}}, nil)
show(s.VC)
r, err := c.Session.WaitForResult(ctx, s.SessionID, nil)
sig, err := c.Validator.ValidateSign(r, digest, eid.SHA256) // 针对 digest
// SignOptions.FileName——文档名称，会显示在 CA 的 /verify 页面和公民的历史记录中（可选）

// 若通过 device-link / push 发起，请核对所用流程（与 ValidateAuth 相同；不一致则返回 *ValidationError）
sig, err = c.Validator.ValidateSign(r, digest, eid.SHA256, eid.ValidateSignOptions{ExpectedFlowType: eid.FlowQR})
```

对于 RAW_DIGEST_SIGNATURE，`flowType` 不属于签名内容（只对 digest 签名）——这是对 RP-API 响应的核对。

**QR / Web2App / App2App**——`c.Sign.DeviceLinkByEtsi` / `DeviceLinkByDocument`（带 `SignOptions.CallbackURL` 时为
Web2App/App2App）；链接通过 `eid.BuildDeviceLink(s.LinkInput(eid.LinkQR, "mon"))` 生成（auth/cert session 同样适用）。
请将 `s.Sign`（`SignContext`：digest、hash、算法、interactions、callback）与 session 一同保存在服务器。

**`ExpiresAt`**——session 结束的时刻：CA 的 session start 响应中的 `expiresAt`（RFC 3339；auth / sign / certificate-choice
均有，自 2026-10-14 起）。旧版 CA（无该字段）下，对 sign / certificate-choice 由 SDK 计算——CA 的默认 600 秒
（`eid.DefaultSignSessionTTL`；CA 管理员可设为 60–1800 秒 → `Config.SignSessionTTL`），对 auth 则为零值。最终以 `GET /session`
（`TIMEOUT`）为准。CA 配置的实时值：`c.Auth.SessionTTL(ctx)`——discovery 的 `sessionTtl`（`Auth`、`Sign`；旧版 CA 为 0）。

**Session 启动错误**（`*eid.APIError`，通过 `errors.Is`）：`eid.ErrNoSigningCertificate`——409 `NO_SIGNING_CERTIFICATE`
（sign / certificate-choice start：公民没有活跃设备 / 有效的签名证书，
未创建 session）；`eid.ErrCertChoiceInvalid`——409 `CERT_CHOICE_INVALID`（linked sign 的 certificate-choice 无效 /
已过期 / 已被使用 → 重新发起）；`eid.ErrRequestInvalid`——400 `REQUEST_INVALID`（例如 linked 中缺少 `linkedSessionID`）。

**预先获知证书（client-side PAdES / CMS）**——由于证书会进入 DTBS（`signingCertificateV2`），应先做
certificate-choice，然后让**恰好那台设备（`documentNumber`）** 对 digest 签名。对于拥有多部手机的公民，
若按 etsi 发起，会由另一部手机签名，签名将与证书不匹配。

```go
cc, err := c.Sign.CertificateChoiceByEtsi(ctx, "PNOMN-12345678", nil) // 或 CertificateChoiceDeviceLink（QR；提供 CallbackURL 时为 Web2App/App2App）
r, err := c.Session.WaitForResult(ctx, cc.SessionID, nil)
signer, err := c.Validator.ValidateCertificateChoice(r, cc.SessionID) // Signer{Certificate, DocumentNumber}
dtbs := buildDTBS(signer.Certificate)                                 // 32 字节 SHA-256，标准 base64
s, err := c.Sign.DigestForSigner(ctx, signer, dtbs, ix, &eid.SignOptions{FileName: "合同.pdf"}) // linked/{documentNumber}
// QR / Web2App: c.Sign.DeviceLinkForSigner(ctx, signer, dtbs, ix, &eid.SignOptions{CallbackURL: …})
r, err = c.Session.WaitForResult(ctx, s.SessionID, nil)
sig, err := c.Validator.ValidateSign(r, s.Sign.Digest, s.Sign.HashAlgorithm, eid.ValidateSignOptions{
	ExpectedFlowType:    eid.FlowNotification,
	ExpectedAlgorithm:   s.Sign.SignatureAlgorithm, // sha256WithRSAEncryption——会拒绝 PSS 响应
	ExpectedCertificate: signer.Certificate,        // 若使用其他证书签名则拒绝
})
```

`DigestForSigner` / `DeviceLinkForSigner` 的默认值：`sha256WithRSAEncryption` + `SHA-256`（CA 的 SplitKey RSA 按请求的
算法签名，PKCS#1 v1.5；旧的 threshold-ECDSA credential 始终是 `ecdsa-with-SHA256`——`ExpectedAlgorithm` 仅在
EC P-256 证书时才接受它）。如果 digest 长度与 hash 不符，请求不会发出。

**在手机上进行 linked 签名（v0.23.0）**——当公民在同一部手机上访问 RP 的网站时：若以
`CertChoiceOptions.CallbackURL` 发起 certificate-choice device link，则可使用 Web2App/App2App 链接（CA 会按 `callbackHosts`
allowlist 校验该字段，并将路径规范化为 `/auth/eid/callback`；不在 allowlist 中则被丢弃，session 仅支持 QR）。
`CertificateChoiceByEtsi`（push）不发送 callback。手机只有在 **linked SIGN 完成之后**才会打开 callback
（linked SIGN session 本身没有 callback）；query：RP 自己的参数（如 `value=<随机值>`）原样不变 +
`sessionSecretDigest` + `sessionId`（certificate-choice 的 session），没有 `userChallengeVerifier`。

```go
// 1. 发起：将 value 存入浏览器的 cookie。
cc, err := c.Sign.CertificateChoiceDeviceLink(ctx, &eid.CertChoiceOptions{
	CallbackURL: "https://rp.example.mn/auth/eid/callback?value=" + value,
})
link, err := eid.BuildDeviceLink(cc.LinkInput(eid.LinkWeb2App, "mon")) // 或 LinkApp2App；QR 使用 LinkQR
// 2. 验证 certificate choice 后发起 linked sign（DeviceLinkForSigner / DigestForSigner——见上方示例）。
r, err := c.Session.WaitForResult(ctx, cc.SessionID, nil)
signer, err := c.Validator.ValidateCertificateChoice(r, cc.SessionID)
// 3. 在 /auth/eid/callback 处：
//    - query 中的 `value` 是否与浏览器的 cookie 相等；
//    - eid.VerifySessionSecretDigest(q.Get("sessionSecretDigest"), cc.SessionSecret) — cc 为服务器端保存的
//      certificate-choice session（通过 sessionId 查找）；SessionSecret 绝不会到达浏览器；
//    - 仅接受该 callback 一次（第二次则拒绝）；
//    - 然后读取 linked SIGN session 的结果（c.Session.WaitForResult → ValidateSign）并作出判断。
```

`eid.SessionSecretDigest(secret)` = `BASE64URL-NOPAD(SHA-256(base64-decode(secret)))`；`VerifySessionSecretDigest` 以
恒定时间比较，对格式错误的输入返回 `false`。收到 callback 并**不**意味着文档已签名——
务必从 session 中读取结果并用 `ValidateSign` 核对。

### 3.4. 以组织名义

公民**使用自己的 PIN2 证书**签名；eID 根据自己的登记核查其代表组织的权限（个人的
qualified 签名——不是组织印章）。为 PDF 签名属于客户端 PAdES——[§7](#7-客户端-pades-pades)。

```go
reps, err := c.Organization.GetRepresentations(ctx, "PNOMN-12345678") // 公民必须在最近 24 小时内登录过
s, err := c.Sign.DigestForSigner(ctx, signer, dtbs, ix, &eid.SignOptions{OnBehalfOf: "NTRMN-6235972"})
// r.OnBehalfOf — 服务器已核验代表权的证明（nil = 个人）
```

若 `OnBehalfOf` 被拒绝，则看 `*eid.ForbiddenError` / `*eid.APIError` 的 `Code`（`eid.OnBehalfErrorCodes`）：
`REPRESENTATION_DENIED`、`REPRESENTATION_PENDING`、`REPRESENTATION_EXPIRED`、`ORG_NOT_ACTIVE`、`SIGNER_UNIDENTIFIED`
（403）· `ORG_NOT_FOUND`（404）· `REPRESENTATION_REVOKED`（403，出现在 `RegisterSignature` 和令牌证书签发中）。

临时性错误——`*eid.APIError.Retryable()` 为 true，应在 `RetryAfter`（CA 的 `Retry-After`，秒数或日期）之后
重试（`eid.RetryableCodes`；不带 code 的 429/503 + `Retry-After` 同样如此）。`Header`——响应的所有 header。

JSON 响应超过 4 MiB 时返回 `*eid.ResponseTooLargeError`（不会截断）。`GetRepresentations` 的 `Raw`——服务器的
原始 JSON。

**向用户展示时请使用 `RoleLabel` / `RightTypeLabel` / `SourceLabel`**（`Representation` 中三者都有，session 的
`OnBehalfOf` 中只有 `RoleLabel` / `RightTypeLabel`——那里没有 `Source`）——`Role`（`ceo` / `founder` / `stakeholder`，或为
MANAGER 填写的文字）、`RightType`（`ADMIN` | `MANAGER`）、`Source`（`REGISTRY` | `MANUAL`）是机器值，请勿自行翻译。语言：`eid.Config{…, Language: "en"}` → 每次调用带 `Accept-Language`；`""` = 不发送（服务器使用 mn）。
旧版 CA 为空。

### 3.5. Session 的 person 块

```go
r, _ := c.Session.WaitForResult(ctx, s.SessionID, nil)
who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{})
if err == nil && eid.PersonMatchesCertificate(r.Person, who.Subject) {
	// r.Person: FirstName (名), LastName (父名), FamilyName (姓氏), CivilID, RegNo, BirthDate, Gender, GeID, Nationality (ISO 3166-1 alpha-3，例如 MNG；可选)
}
// r.Raw — 服务器的原始 JSON（用于 SDK 未解析的字段）
```

Person 块**不包含在**签名中——必须与证书的 `SERIALNUMBER`（`PNOMN-<civilId>`）比对一致后才能信任。

### 3.6. 公民 PKI 面板（`PKI_READ` 权限）

`c.Person.Certificates` · `Devices` · `Activity(ctx, etsi, &eid.ActivityQuery{Flow, Limit, Offset})` · `Summary` ·
`Children`——公民必须在最近 24 小时内通过您的 RP 登录过（否则 403）。每个响应都带有 `Raw`。

`PersonCertificate`（自 v0.5.0 起）有 `IssuedAt`（签发时间）、`RevokedAt`（吊销时间——REVOKED）、`RevocationReason`（RFC 5280
名称：`keyCompromise`、`superseded`、`cessationOfOperation` ……）。`Status` 不会改变：因续期/重新登记而被替换的
记录为 `SUSPENDED` + `RevocationReason: "superseded"`，`RevokedAt` 为 nil。

`KeyMedium == "TOKEN"` 的记录带有 `Organization`（组织令牌，个人令牌为 nil）和 `TokenSerial`——证书所签发到的
USB 令牌的序列号。不要按组织/日期去猜同一令牌的 AUTH + SIGN，请按 `TokenSerial` 分组
（因续期而被替换的记录同样带有自己令牌的编号）。MOBILE/HSM 记录以及旧版 CA 为 `""`。

### 3.7. USB 令牌

```go
// 证书签发（TOKEN_ISSUE 权限）——公民在手机上用 PIN2 确认
in := eid.TokenCertInput{SignerEtsi: etsi, CSRAuth: csrA, CSRSign: csrS,
	TokenSerial: "EP2003-0042A1", OnBehalfOf: ""} // "" = 个人令牌
// push 之前：用相同输入做 dryRun——不创建 session/push，错误代码与真实调用相同
pv, err := c.Token.PreviewCertificate(ctx, in) // 若 pv.Supersedes 存在，先警告公民并取得同意，再 ↓
st, err := c.Token.IssueCertificate(ctx, in)
// st.Supersedes——个人签发将替换的此前的个人令牌（见下）；在 PIN2 之前提醒公民
if l, ok := eid.TokenLimitOf(err); ok { /* 409 TOKEN_LIMIT_REACHED: l.Kind, l.Limit, l.Organization */ }
// 409 eid.CodeTokenInUse — 该序列号属于另一位公民；409 eid.CodeTokenScopeChange——续期会更改 scope（见下）
// 400 eid.CodeAppAttestationInvalid — 提供了 AppTransaction 但无效（见下）
// … c.Session.Poll → r.TokenCertificate.Status == eid.TokenCertIssued
res, err := c.Token.CertificateResult(ctx, st.SessionID)
err = eid.VerifyTokenCertificates(res, csrA, csrS) // 每个证书都与其 CSR 的密钥一致

// 使用令牌登录（AUTH 权限）
ch, err := c.Token.AuthChallenge(ctx)
digest, _ := eid.TokenAuthDigest(ch.RPUUID, ch.Challenge) // 令牌的 CKM_ECDSA → 原始 r||s
// 自 v0.6.0 起需完整传入 challenge（由 RP 保存，或由客户端回传——CA 通过 ChallengeID 比对）：
// SDK 不会仅凭 CA 的 OK 就信任——它会用证书密钥验证 r||s，将 RPUUID 与自己的比对，并按 Trust 验证证书
// （证书链、颁发者、用途为 auth），然后才发送给 CA。
who, err := c.Token.AuthVerify(ctx, ch, authCertDER, rs)

// 使用令牌签 PDF——客户端 PAdES（§7）：令牌对 DTBS 签名，RegisterSignature 中使用 Medium: eid.PDFMediumToken
```

**续期会保留 scope**（CA 2026-10-16，discovery `tokenCertificate.scopeLockedOnRenewal: true`——
`c.Token.CertificateInfo(ctx)`）：若公民在同一 `TokenSerial` 上已有 ACTIVE 记录，则签发即续期；组织
令牌只能用于该组织（`OnBehalfOf` 相同），个人令牌只能作个人使用。若 scope 不同，`IssueCertificate`
（或在确认后的 `CertificateResult`）返回 409 `eid.CodeTokenScopeChange`（`TOKEN_SCOPE_CHANGE`），session 的
`TokenCertificate.ErrorCode` 同样如此——没有 override。更改 scope = 公民在 eID 应用中吊销令牌
（`/v3/mobile/tokens/{tokenSerial}/revoke`）后重新签发；对用户的提示：“要更改令牌类型（个人/组织），
请在 eID 应用中吊销该令牌后重新签发。”

**个人令牌的自动替换**（CA 2026-10-19，discovery `tokenCertificate.personalAutoSupersede: true`）：当个人
数量达到上限时，使用不同 `TokenSerial` 的新个人令牌不再返回 409——而是返回 `st.Supersedes`（`[]eid.TokenSupersede{TokenSerial}`）；对个人
令牌的新签发成功后（PIN2 + 证书），之前个人令牌的 AUTH + SIGN 会以 superseded (4) 被吊销。
被拒绝 / 已过期的签发不会影响之前的令牌。在 PIN2 之前提示：“您之前的 USB 令牌（EP2003-…）的证书
将失效。”409 `TOKEN_LIMIT_REACHED` 的 `kind=PERSONAL` 仅在 `limit=0`（个人签发被关闭）时出现；
组织令牌（`ORGANIZATION`）仍是硬性限制。

**dryRun——push 之前的检查**（CA 2026-10-19，discovery `tokenCertificate.dryRun: true`——
`CertificateInfo().DryRun`）：当 `IssueCertificate` 的响应中出现 `Supersedes` 时，PIN2 push 已经发往手机——
即使在桌面端取消，只要公民在手机上确认，旧令牌仍会被替换。因此流程为：CSR → `c.Token.PreviewCertificate(ctx, in)`
（请求体相同 + `"dryRun": true`；执行所有检查，错误代码相同——包括 CSR 主机不同的待处理签发所返回的
`409 TOKEN_ISSUANCE_PENDING`；不会创建 session / push / state）→ 若有 `Supersedes` 则警告，让公民同意 →
`IssueCertificate(ctx, in)`。限流（RP、公民）为 20/分钟，RP 总计 120/10 分钟——不会消耗 push 的 3/小时。若响应中没有返回 `dryRun: true`，则返回 `*eid.ValidationError`（旧版 CA 对不认识的字段返回 400）。

**应用证明（`AppTransaction`，可选）**（CA 2026-10-19，discovery `tokenCertificate.appTransaction:
"optional"`）：macOS App Store 构建会从桌面端传递 StoreKit 2 `AppTransaction` 的 JWS（compact）字符串——
`eid.TokenCertInput{…, AppTransaction: jws}`。CA 不会调用 Apple 的服务器，而是离线检查；若提供则必须
有效，否则返回 400 `eid.CodeAppAttestationInvalid`（`APP_ATTESTATION_INVALID`，不会说明是哪一步失败，也不会
向手机发送 push）。`""`（Windows）= 无证明的签发。超过 `eid.MaxAppTransactionBytes`（16 KiB）时 SDK 不会发送，而是
返回 `eid.ErrAppTransactionTooLarge`。向旧版 CA（`CertificateInfo().AppTransaction == ""`）发送该字段会返回 400。

`/token/auth/*` 已列入 `/.well-known/eid` 的 `endpoints.token.auth_challenge` / `auth_verify`（AUTH 权限）——
合约测试会像检查其他 route 一样检查它。

### 3.8. 通过电子邮件发送已签名文件——`c.Share`（`SIGN` 权限）

将您已签名的 PDF 作为附件发送给下一位签名人 / 收件人（`POST /share`）。CA **不会保存**该文件：它会检查
文件是否带有有效的 eID 签名，发送后即丢弃。每位收件人收到单独的一封邮件。

> 在 CA 上始终开启（自 2026-10-16 起不再有开关）。限制和配额请从 `c.ShareInfo(ctx)` 读取；
> 若 `Enabled` 为 false，则邮件服务暂未配置（503）。

```go
info, err := c.ShareInfo(ctx) // Enabled, MaxFileBytes, MaxRecipients, Quota{PerRPHour, PerRPDay, PerRecipientDay}, …
if err == nil && info.Enabled {
	res, err := c.Share(ctx, eid.ShareRequest{
		File:     signedPDF,                // ≤ 3 080 192 字节，带有效 eID 签名的 PDF
		Filename: "合同.pdf",              // 须带 .pdf 扩展名；"" = document.pdf
		To:       []string{"next@example.mn"}, // 1–5 个，不可重复
		Subject:  "合同——签名",      // ≤ 150; CA 会添加“‹RP 名称›: …”前缀
		Message:  "请添加第二个签名", // ≤ 1000
		Lang:     "mn",                      // mn | en
	})
	var se *eid.ShareError
	switch {
	case errors.As(err, &se) && se.Code == eid.CodeMailFailed:
		// se.Recipients[i] == eid.ShareRecipientFailed——仅向这些收件人重新发送
	case errors.As(err, &se) && se.Code == eid.CodeFileNotSigned:
		// se.Reason: eid.ShareReasonNoSignature | ShareReasonInvalid | ShareReasonUntrusted
	case err == nil:
		_ = res.DocID // 若已在 CA 登记（邮件中会带 verify 链接）
	}
}
```

| HTTP | `ShareError.Code` | 说明 |
|---|---|---|
| 400 | `REQUEST_INVALID`, `FILE_EMPTY`, `RECIPIENT_REQUIRED`, `TOO_MANY_RECIPIENTS`, `RECIPIENT_INVALID`, `RECIPIENT_DUPLICATE` | 字段错误 |
| 413 | `FILE_TOO_LARGE` | 文件 / 邮件超过限制 |
| 415 | `FILE_TYPE_NOT_SUPPORTED` | 不是 PDF（扩展名、Content-Type、`%PDF-` 三者必须一致） |
| 422 | `FILE_NOT_SIGNED` | `.Reason`：`no_signature` \| `invalid` \| `untrusted` |
| 429 | `RATE_LIMITED` | 配额；`.RetryAfter`、`.Retryable()` |
| 502 | `MAIL_FAILED` | `.Sent`、`.Failed`、`.Recipients`（按 `To` 的顺序为 `sent` \| `failed`） |
| 503 | `MAIL_UNAVAILABLE`、`VALIDATOR_UNAVAILABLE`、`VALIDATOR_BUSY`（`SHARE_DISABLED`——旧版 CA） | 配置 / 负载（`VALIDATOR_*`——Retry-After） |

401 → `*eid.AuthenticationError`，403（没有 SIGN 权限、IP/mTLS）→ `*eid.ForbiddenError`。配额：每个 RP 每小时 300 / 每天 3000
次请求，每位收件人每天 10 封邮件（实际值请取自 `ShareInfo().Quota`）。超时为 `DefaultShareTimeout`（150 s）；
若 ctx 的 deadline 更短，则以其为准。

### 3.9. “我的 QR”——当面验证（`c.QR`，v0.21.0）

公民在 eID 应用中展示“我的 QR”（`EIDMN-QR1:<token>`，120 s，一次性）。RP（收银台、POS、应用）扫描后
调用 `c.QR.Start` → 公民手机上出现一句话（“您将与 <RP> 共享“我的信息”部分的全部信息”）
+ PIN2 → RP 获得公民的整个“我的信息”（按来源的键，原样保留）以及人脸图像，
并带有**公民的 QUALIFIED 签名**（PS256 JWS，`x5c` = [SIGN 证书, 颁发 CA]）。RP 只需要 `QR_PRESENT` 权限。
CA 不保存数据副本——presentation **只能读取一次**（再次读取 → 410）。

```go
token, err := eid.ParseQR(scanned) // 或 c.QR.Parse；若不是 "EIDMN-QR1:<43>" → errors.Is(err, eid.ErrQRFormatInvalid)
sess, err := c.QR.Start(ctx, eid.QRStartRequest{
	QR:    scanned,
	Nonce: orderID, // 可选：16–128 个可打印 ASCII；"" = 22 个随机字符
})
if errors.Is(err, eid.ErrQRTokenInvalid) { /* 404：已过期 / 已被使用 → 请重新生成 QR */ }

// sess 可以保存（JSON）——Result 会核对 sid 和 nonce。轮询 UI： c.QR.Check(ctx, sess, 0).
p, err := c.QR.Result(ctx, sess, nil)
var sf *eid.SessionFailedError // USER_REFUSED, TIMEOUT …
var qe *eid.QRError
switch {
case errors.As(err, &sf):
case errors.Is(err, eid.ErrQRPending): // 等待时间已用尽，但 session 仍有效——请再次调用 Result / Check
case errors.Is(err, eid.ErrQRPresentationGone): // 410：已被读取 → 请使用新的 QR
case errors.As(err, &qe): // QR_CHAIN_INVALID, QR_SIGNATURE_INVALID … ——不要信任
}
for _, k := range p.Keys { fmt.Println(k, p.Data[k]) } // payload 的顺序
_ = p.Photo                     // JPEG 字节（或 nil）
_ = p.Signer.ETSI               // = sub，即证书的 serialNumber（PNOMN-…）
_ = p.SHA256                    // = CA 审计中的 qrsha（用于争议核对）
```

验证（`eid.VerifyQRPresentation(ctx, jws, eid.QRExpect{…}, trust)`——三个 SDK 相同，使用 CA 的
`testdata/myqr_vectors.json`）：compact JWS ≤ 512 KiB → header 必须恰好是 `{alg: PS256, typ: eidmn-myqr+jwt, x5c: [2]}` →
证书链 leaf →（x5c[1] ∪ intermediates）→ anchor（± 60 s；leaf 非 CA，KU contentCommitment，QUALIFIED，RSA ≥ 2048，颁发者
SKI allowlist）→ 吊销（`Trust.Revocation`；若为 nil 则用 `NewOCSPChecker`，默认 hard-fail）→ 针对收到的字节验证 RSASSA-PSS（SHA-256，salt
32）→ claim（`iss`、`sub` = cert serialNumber、`statement` = 由 rp_name 组成的句子）→ `aud`（不区分大小写）
→ `sid` → `nonce` → `0 < exp−iat ≤ 300`、`iat ≤ 现在+60`、`现在 < exp+60` → `data`（`source`
`^[a-z0-9_-]{1,32}$`，`fields` ≤ 128 项（键 1–64 个字符，值 ≤ 2048 字节），`photo` 为严格 base64 的 JPEG
≤ 150 KiB）。每个错误都是 `*QRError{Code}`（`QR_JWS_MALFORMED`、`QR_HEADER_INVALID`、`QR_CHAIN_INVALID`、`QR_CERT_REVOKED`、
`QR_REVOCATION_UNKNOWN`、`QR_SIGNATURE_INVALID`、`QR_CLAIMS_INVALID`、`QR_AUDIENCE_MISMATCH`、`QR_SESSION_MISMATCH`、
`QR_NONCE_MISMATCH`、`QR_NOT_YET_VALID`、`QR_EXPIRED`、`QR_DATA_INVALID`）+ `ErrQR*` sentinel。信任 = `Config.Trust`：
若 `TrustAnchorsPEM` 为空，则用 SDK 的 `NationalRootCAPEM`（`AllowUntrusted` 在此不生效），颁发者默认为
`CitizenIssuingCASKI`。

CA 的其他代码：404 `QR_TOKEN_INVALID` / 410 `QR_PRESENTATION_GONE` → `*QRError`（`Cause` = `*APIError`）；400
`REQUEST_INVALID`、403 `PERMISSION_DENIED` / `RP_REQUIRED`（`*ForbiddenError`）、409 `NO_SIGNING_CERTIFICATE`、429
`RATE_LIMITED`（`*APIError`）。`Config.QR.Issuer`——仅用于测试环境。

### 3.10. 组织电子印章（e-Seal）——`c.Seal`（v0.24.0）

以组织名义，由**无人值守的自动化**系统对文档加盖印章（发票、证明、对账单）：密钥保存在 eID 的
服务器上，不涉及公民/PIN/应用，响应即时返回（无 session）。RP 需要该组织的 **`SEAL:<orgEtsi>`** 权限——
该权限**由组织自己授权**（见下文“印章权限、密钥、有效期”）；没有权限则返回 `*ForbiddenError` 403。
若是公民以组织名义签名，请参见 §3.4（不是印章）。

```go
sc, err := c.Seal.Certificate(ctx, "NTRMN-6235972")            // GET /seal/certificate/{orgEtsi} — 当前已签发的印章证书
r, err := c.Seal.Seal(ctx, "NTRMN-6235972", digest, eid.SHA256) // POST /seal/{orgEtsi} — {digest, hashType}
// r.Signature — 对 digest 的 ECDSA（DER）签名，r.Certificate——印章证书（DER），r.SealedAt
```

- `Seal` 会校验响应：签名必须能用响应中的证书对 digest 验证通过，且证书必须是 e-Seal profile
 （`eid.IsSealCertificate`：KeyUsage 仅为 nonRepudiation，没有 EKU 用途——extendedKeyUsage 不存在或为空）——否则返回 `*ValidationError`。证书链和
  吊销由 `pades.SealPDF`（OCSP/CRL + self-validation）检查。
- `hashType`：`eid.SHA256`（默认）| `SHA384` | `SHA512`；若 digest 长度不符，则不会发出网络请求。
- **429 `RATE_LIMITED`**——`*APIError`，若 `Retryable()` 为 true，则在 `RetryAfter` 之后重试（每个 RP 每分钟 300 次盖章）。
  404——找不到组织；**409**——每个 code 都有自己的 sentinel（见下表，v0.27.0）。
- **503 `SEAL_SERVICE_DISABLED`**——见下文“服务开关”（不要重试）。
- `CertificateLevel`（`SealCertificate`、`SealResult`）取自**证书本身**（有 QcSSCD 则为 `QSCD`，否则为
  `QUALIFIED`）——而不是 CA 当前的密钥配置。
- `Certificate` 返回组织**当前（已签发、有效）** 的证书——不会新签发；若未签发 /
  已吊销 / 不在有效期内，则返回 **409**（`ErrSealNotIssued` | `ErrSealCertRevoked` | `ErrSealCertExpired` |
  `ErrSealCertNotYetValid`）——绝不会以 200 返回无效证书。为 PDF 盖章：§7.3 `pades.SealPDF`。

#### 印章权限、密钥、有效期（v0.27.0）

- **权限（`SEAL:<orgEtsi>`）——经组织同意。** eID 运营方为您的 RP 创建权限**申请**；只有在该
  组织**经国家登记验证**的 ADMIN 在 eID 应用中看到 RP 的名称、域名、组织名称和注册号，并用 **PIN2** 批准之后，权限才会产生。在批准之前（即使被拒绝、已过期），盖章和
  证书申请（`Seal`、`pades.SealPDF`、`RequestCertificate`、`CertificateRequest`）都返回 `*ForbiddenError` 403
 （`Certificate` 不需要权限）。若运营方撤销权限或组织被注销，权限即失效（403）。在
  拥有权限期间，不能更改 RP 的名称、callback host 和 mTLS 证书 subject（运营方一侧的规则——若要更改，
  必须重新获取权限）。
- **密钥。** 印章密钥为 ECDSA P-256，是保存在 eID 服务器上的**软件密钥**（由 HSM 密钥
  包装）——**不是 QSCD**。证书级别为 `QUALIFIED`（依据蒙古国法律；没有 QcSSCD）——并非欧盟 qualified。
- **有效期、续期。** 证书有效期 3 年。续期 = 新申请（`RequestCertificate`）：会生成新密钥、新
  证书，之前的证书被吊销（superseded）。用之前的证书盖章的文档，只要带有时间戳就仍然有效——
  `pades.SealPDF` 的输出（PAdES-BASELINE-LT）满足这一点。
- **吊销。** 吊销之后，`Seal` / `pades.SealPDF` / `Certificate` → `ErrSealCertRevoked`；在吊销**之前**
  盖章的文档在验证中仍然有效（`revoked_after_signing`）。
- **第三方验证器。** 证书链直至蒙古国国家 Root CA；证书中带有 OCSP / CRL 地址。除非手动信任国家 Root，
  否则 Adobe 和欧盟的验证器不会将印章显示为受信任 / qualified。

| HTTP `code` | `errors.Is` | 位置 | 如何处理 |
|---|---|---|---|
| 409 `ORG_NOT_ACTIVE` | `eid.ErrOrgNotActive` | `Seal`、`SealPDF`、`RequestCertificate` | 组织不是 ACTIVE——恢复之前不要重试 |
| 409 `SEAL_NOT_ISSUED` | `eid.ErrSealNotIssued` | `Seal`、`SealPDF`、`Certificate` | 证书尚未签发——`RequestCertificate` |
| 409 `SEAL_CERT_REVOKED` | `eid.ErrSealCertRevoked` | `Seal`、`SealPDF`、`Certificate` | 已吊销——申请新证书 |
| 409 `SEAL_CERT_EXPIRED` | `eid.ErrSealCertExpired` | `Seal`、`SealPDF`、`Certificate` | 已过期——申请新证书 |
| 409 `SEAL_CERT_NOT_YET_VALID` | `eid.ErrSealCertNotYetValid` | `Seal`、`SealPDF`、`Certificate` | 有效期尚未开始 |
| 409 `SEAL_KEY_UNAVAILABLE` | `eid.ErrSealKeyUnavailable` | `Seal`、`SealPDF` | 服务器配置中缺少密钥——联系 eID 支持 |
| 409 `SEAL_APPROVER_UNAVAILABLE` | `eid.ErrSealApproverUnavailable` | `RequestCertificate` | 没有拥有活跃 eID 的 ADMIN |
| 404 `SEAL_REQUEST_NOT_FOUND` | `eid.ErrSealRequestNotFound` | `CertificateRequest`、`WaitForCertificate` | 申请 id 错误 |
| 503 `SEAL_SERVICE_DISABLED` | `eid.ErrSealServiceDisabled` | `Seal`、`SealPDF`、`RequestCertificate` | 运营方已关闭——不要重试 |

全部是 `*eid.APIError`（`Status`、`Code`、`Body` 不变；`Retryable()` 为 false）；代码列表见 `eid.SealErrorCodes`。
`eid.ErrOrgNotActive` 也会匹配 OnBehalfOf 流程中 403 的 `*ForbiddenError`（`ORG_NOT_ACTIVE`）。

```go
_, err := pades.SealPDF(ctx, c.Seal, org, pdf, pades.SealOptions{})
switch {
case errors.Is(err, eid.ErrSealNotIssued), errors.Is(err, eid.ErrSealCertRevoked), errors.Is(err, eid.ErrSealCertExpired):
	// 没有有效的印章证书 → c.Seal.RequestCertificate（组织的 ADMIN 用 PIN2 确认）
case errors.Is(err, eid.ErrOrgNotActive):
	// 组织已暂停 / 已吊销——不要重试
}
```

#### 申请印章证书（v0.25.0）

证书既不由 RP 也不由运营方直接签发——而是创建一个**申请**。组织每个有效的 **ADMIN** 代表（拥有活跃
eID 设备，≤ 5 人）会在 eID 应用中收到申请，并用 **PIN2** 确认。只要有一位 ADMIN 确认，证书即签发（`ISSUED`）；
若拒绝则为 `REJECTED`；若批准期限（签名 session 的 TTL + 2 分钟）结束则为 `EXPIRED`。

```go
req, err := c.Seal.RequestCertificate(ctx, "NTRMN-6235972") // 202: req.RequestID, req.Status == eid.SealRequestPending
if errors.Is(err, eid.ErrSealApproverUnavailable) {
	// 该组织没有拥有有效 eID 的 ADMIN
}
sc, err := c.Seal.WaitForCertificate(ctx, "NTRMN-6235972", req.RequestID, &eid.SealWaitOptions{Timeout: 10 * time.Minute})
var se *eid.SealRequestError
if errors.As(err, &se) {
	// se.Outcome: REJECTED | EXPIRED | FAILED → 新的申请；eid.SealRequestTimeout → 可用相同的 RequestID 继续等待
}
```

- `RequestCertificate`——`POST /seal/certificate/{orgEtsi}` → `*SealCertificateRequest`（`RequestID`、`Status`、
  `CreatedAt`、`ExpiresAt`、`Approvers`）。若该组织已有 PENDING 申请，CA 会返回它（不会新发 push）。
- `CertificateRequest(ctx, org, requestID)`——`GET /seal/certificate/{orgEtsi}/requests/{requestId}`：`Status` = `PENDING` |
  `APPROVED`（正在签发）| `ISSUED`（`Certificate` 已填充）| `REJECTED` | `EXPIRED` | `FAILED`（`Failure`：
  `SEAL_ISSUANCE_FAILED` | `PUSH_FAILED` | `SEAL_SERVICE_DISABLED`）。
- `WaitForCertificate(ctx, org, requestID, *SealWaitOptions{Timeout = 15 分钟, Interval = 3 秒})`——轮询直到 ISSUED 并返回
  `*SealCertificate`；REJECTED / EXPIRED / FAILED / 超时 → `*SealRequestError`。遇到 429/503 + Retry-After
 （`*APIError.Retryable()`）时——等待 `RetryAfter` 后继续；若 `ctx` 被取消则返回 `ctx.Err()`。
- 错误：**409 `SEAL_APPROVER_UNAVAILABLE`**（`errors.Is(err, eid.ErrSealApproverUnavailable)`）；**409 `ORG_NOT_ACTIVE`**
 （`eid.ErrOrgNotActive`，v0.27.0；此前为不带 code 的 409）——组织不是 ACTIVE；**404 `SEAL_REQUEST_NOT_FOUND`**（`eid.ErrSealRequestNotFound`；另一个组织的 id 同样如此）；403
  `*ForbiddenError`（没有 `SEAL:<orgEtsi>` 权限）；**429 `RATE_LIMITED`** + `RetryAfter`——每个组织每小时 5 次申请；
  **503 `SEAL_SERVICE_DISABLED`**（`eid.ErrSealServiceDisabled`）——签发已关闭。

#### 由 RP 自行申请印章权限——`RequestGrant`（v0.29.0）

除了由运营方申请之外，RP 也可以**自行**申请组织的 `SEAL:<orgEtsi>` 权限。对方不是通过 ETSI 来确定的——
而是通过**由您的 RP 发起、并在最近 5 分钟内以 OK 结束的认证 session**；该人必须是组织
**经国家登记验证的首席执行官（CEO）**。push 只会发给他，由他在 eID 应用中用 **PIN2** 批准。一个
session → 一次申请（用同一个 session 再次调用会返回同一个 PENDING，不会新发 push）。无需 SEAL 权限。

```go
// 1) 通过您的 RP 让 CEO 重新登录（Auth.*），在 session 变为 OK 后 5 分钟内：
g, err := c.Seal.RequestGrant(ctx, "NTRMN-6235972", authSessionID) // 202: g.GrantID, g.Status == eid.SealGrantPending
switch {
case errors.Is(err, eid.ErrNotOrgCEO): // 403——登录的人不是首席执行官
case errors.Is(err, eid.ErrAuthSessionTooOld), errors.Is(err, eid.ErrAuthSessionAlreadyUsed): // 409——请重新登录
case errors.Is(err, eid.ErrSealGrantAlreadyApproved): // 409——权限已存在
}
// 2) 直到 CEO 用 PIN2 批准：
g, err = c.Seal.WaitForGrant(ctx, g.GrantID, &eid.SealWaitOptions{Timeout: 10 * time.Minute})
var ge *eid.SealGrantError
if errors.As(err, &ge) {
	// ge.Outcome: REJECTED | EXPIRED | FAILED | REVOKED（ge.Failure）→ 重新登录并发起新的申请；
	// eid.SealGrantTimeout → 可用相同的 GrantID 继续等待
}
```

- `RequestGrant`——`POST /seal/grants {orgEtsi, sessionId}` → `*SealGrant`（`GrantID`、`OrgEtsi`、`Status`、`ExpiresAt`）。
- `GrantStatus(ctx, grantID)`——`GET /seal/grants/{grantId}`：`PENDING` | `APPROVED`（`ApprovedAt`）| `REJECTED` | `EXPIRED`
  | `FAILED` | `REVOKED`（`RevokedAt`；`Failure`——`EXPIRED`、`PUSH_FAILED`、`RP_NOT_ACTIVE`、`ORG_NOT_ACTIVE`、
  `RP_CHANGED`、`RP_PERMISSIONS_FULL`、`CANCELLED`、`ORG_REVOKED`）。另一个 RP 的 id → 404 `ErrSealGrantNotFound`。
- `WaitForGrant(ctx, grantID, *SealWaitOptions)`——轮询直到 APPROVED（规则与 `WaitForCertificate` 相同：会遵循 429/503 +
  Retry-After，其他错误立即返回，若 `ctx` 被取消则返回 `ctx.Err()`）。
- `c.Organization.SealGrants(ctx, personEtsi)`——`GET /organization/seal-grants/etsi/{personEtsi}`（`PKI_READ`；公民
  在最近 24 小时内通过您的 RP 登录过）：公民担任 CEO 的每个组织（`OrgEtsi`、`OrgName`、
  `OrgStatus`）及其 APPROVED / PENDING 权限（`RPName`、`RPDomain`、`Status`、`CreatedAt`、`DecidedAt`、
  `ExpiresAt`、`ApproverName`、`SealCount`、`SealCount30d`、`LastSealedAt`）。`SealCount` / `SealCount30d` 为 nil = 统计
  暂不可用（不是 0）。其他 RP 的权限，CA 只在 eID 门户中展示——您的 RP 只能看到自己的权限。
  只读——吊销需在 eID 应用中进行。

| HTTP `code` | `errors.Is` | 如何处理 |
|---|---|---|
| 400 `REQUEST_INVALID` | `eid.ErrRequestInvalid` | orgEtsi / sessionId 错误 |
| 403 `RP_NOT_REGISTERED` | `eid.ErrRPNotRegistered`（`*ForbiddenError`） | 不是已注册的 RP |
| 403 `NOT_ORG_CEO` | `eid.ErrNotOrgCEO`（`*ForbiddenError`） | 登录的人不是首席执行官 |
| 404 `AUTH_SESSION_NOT_FOUND` | `eid.ErrAuthSessionNotFound` | session 不存在 / 属于另一个 RP |
| 404 `ORG_NOT_FOUND` | `eid.ErrOrgNotFound` | 组织未登记 |
| 409 `AUTH_SESSION_WRONG_FLOW` | `eid.ErrAuthSessionWrongFlow` | 不是认证 session |
| 409 `AUTH_SESSION_NOT_COMPLETED` | `eid.ErrAuthSessionNotCompleted` | 登录未完成 / 失败 |
| 409 `AUTH_SESSION_TOO_OLD` | `eid.ErrAuthSessionTooOld` | 超过 5 分钟——重新登录 |
| 409 `AUTH_SESSION_ALREADY_USED` | `eid.ErrAuthSessionAlreadyUsed` | 重新登录 |
| 409 `ORG_NOT_ACTIVE` | `eid.ErrOrgNotActive` | 组织不是 ACTIVE |
| 409 `RP_NOT_ACTIVE` | `eid.ErrRPNotActive` | RP 未启用 |
| 409 `SEAL_GRANT_ALREADY_APPROVED` | `eid.ErrSealGrantAlreadyApproved` | 权限已存在 |
| 409 `RP_PERMISSIONS_FULL` | `eid.ErrRPPermissionsFull` | 请联系 eID 运营方 |
| 409 `SEAL_APPROVER_UNAVAILABLE` | `eid.ErrSealApproverUnavailable` | 首席执行官没有活跃的 eID 设备 |
| 404 `SEAL_GRANT_NOT_FOUND` | `eid.ErrSealGrantNotFound` | （`GrantStatus`）id 错误 / 属于另一个 RP |
| 429 `RATE_LIMITED` | `*APIError.Retryable()` | 在 `RetryAfter` 之后 |

代码列表见 `eid.SealGrantErrorCodes`。

#### 服务开关——`SEAL_SERVICE_DISABLED`

eID 运营方可以在整个平台范围内分别关闭**印章证书签发**和**盖章**。关闭时，
`RequestCertificate`（`service: "issuance"`）以及 `Seal` / `pades.SealPDF`（`service: "sealing"`）会收到
`503 {"error", "code": "SEAL_SERVICE_DISABLED", "service"}`——不带 `Retry-After`。

```go
r, err := c.Seal.Seal(ctx, org, digest, eid.SHA256)
if errors.Is(err, eid.ErrSealServiceDisabled) {
	var ae *eid.APIError
	if errors.As(err, &ae) {
		// ae.Status == 503, ae.Service == eid.SealServiceSealing | eid.SealServiceIssuance, ae.Retryable() == false
	}
	// 不要自动重试——向用户显示“服务暂时关闭”，并将其留在队列中
}
```

- 对于此 code，`*APIError.Retryable()` **始终为 false**（即使 proxy 添加了 `Retry-After`）——SDK（`WaitForCertificate`、
  `pades.SealPDF`）不会重试，而是原样返回错误；由于 CA 不会告知何时恢复，RP 也不应做短间隔的重试循环。
- 若待处理的申请已被 ADMIN 批准但签发已关闭，则申请变为 `FAILED`，`Failure` =
  `SEAL_SERVICE_DISABLED`，不会签发证书：`WaitForCertificate` → `*SealRequestError`，同时
  `errors.Is(err, eid.ErrSealServiceDisabled)` 为 true。恢复后请重新发起 `RequestCertificate`。
- 永远不会关闭的：`Certificate`、`CertificateRequest`（状态查询）、验证（`/validate/*`、`pades.ValidatePDF`）、
  OCSP/CRL、吊销——此前盖章的文档仍然有效。
- 当前状态位于 `/.well-known/eid` 的 `seal` 块中：`{"issuanceEnabled", "sealingEnabled", "disabledCode"}`。

## 4. 安全性——为什么必须使用 `Validator`

**不要单凭 `EndResult == "OK"` 就信任结果**——若 RP-API 被破坏/被代理，可能会收到伪造的 OK。
`Validator`（<https://developer.eidmongolia.mn/#verification>）：

1. `State == COMPLETE`（否则返回 `*ValidationError`——例如 `WaitForResult` 返回的 RUNNING），且 `EndResult == OK`（否则
   返回 `*SessionFailedError`）。
2. 沿证书链将公民证书一直验证到 **trust anchor（Mongolian National Root CA，`eid.NationalRootCAPEM`）**
  （Root 01 → National Issuing CA 02 → Gerege Issuing CA 03 → eID Mongolia Issuing CA 04 → 公民）——Go 的
   `x509.Certificate.Verify`（RFC 5280）：CA basicConstraints + **pathLenConstraint**（04 为 `pathlen:0`）、CA 的
   keyUsage keyCertSign、**name constraints**、**EKU**（auth → clientAuth，sign → emailProtection——CA 的 profile；
   若中间 CA 有 EKU，则必须落在其范围内）、无法识别的 **critical extension** → 拒绝，以及签名、有效期（按
   leaf 的有效期检查证书链，容许 `ClockSkew` 范围内的偏差）。未配置 trust anchor 时 **fail-closed**
  （`AllowUntrusted` 仅用于 dev/测试）。不信任操作系统的 trust store。响应中不携带证书链——若 `IntermediatesPEM` 为 nil，
   则使用 SDK 内置的 02、03、04（`eid.CitizenIntermediatesPEM`，自 v0.6.0 起）。不检查链中的 certificatePolicies
  （CA 的证书链中没有 policyConstraints；检查的是级别——第 3 步）。
3. 证书在有效期内（`ClockSkew`）+ 满足所需级别（`RequiredLevel`，默认 `QUALIFIED`；`QSCD` 也满足）。
   **自 v0.6.0 起，级别由证书本身确定**（`eid.CertificateLevelOf`）：对签名证书，qcStatements
   QcCompliance → QUALIFIED（+ QcSSCD → QSCD；手机以及 2026-11-06 之后签发的 USB 令牌为 QUALIFIED），没有 qcStatements
  （此前签发的令牌）→ ADVANCED；对认证证书，由于 CA 不写入 qcStatements，因此按 profile 判定 → QUALIFIED：
   KeyUsage keyEncipherment（手机的 P-CITIZEN-AUTH），或 EKU clientAuth + emailProtection 且带国家 policy
   `2.16.496.1.101.1.2.8`（令牌的 P-CITIZEN-AUTH-TOKEN，自 v0.22.2 起）；其余 → ADVANCED。若响应中的 `CertificateLevel`
   高于该值则拒绝；低于该值则采用响应中的值（CA 将旧令牌的 AUTH 声明为 ADVANCED）。
   `VerifiedIdentity` / `VerifiedSignature` / `Signer` 的 `CertificateLevel` = 此值。
4. 签名（`rsassa-pss` / `shaNNNWithRSAEncryption` / `ecdsa-with-SHA256`）：
   - **auth** → ACSP_V2 payload（`smart-id|ACSP_V2|serverRandom|rpChallenge|userChallenge|B64(rpName)|B64(brokeredRpName)|B64(SHA-256(interactions))|interactionTypeUsed|initialCallbackUrl|flowType`），
     hash = 请求的 `HashAlgorithm`；`flowType` 必须在所提供的流程之内，若提供了 `ExpectedFlowType` 则必须完全一致，
     Web2App/App2App 必须提供 `UserChallengeVerifier`；`initialCallbackUrl` 只能是 `""` 或您的 callback。
   - **sign** → 针对您的 digest（prehashed）；若提供了 `ValidateSignOptions.ExpectedFlowType`，响应的 `flowType` 必须完全一致
    （它不属于签名内容——是对响应的核对）。
   - 核对算法 ↔ 密钥类型（RSA 的名称只能配 RSA 证书）；hash 必须与请求的完全一致（防降级）。
     ECDSA 仅限 `ecdsa-with-SHA256` + EC P-256 + SHA-256 的 session（CA 的 ECDSA credential 只对
     SHA-256 签名；若 SHA-384/512 的 session 收到 ECDSA 响应，则返回 `ValidationError`）。
5. 吊销——`TrustConfig.Revocation`（OCSP/CRL hook，默认 `RevocationHardFail`）→ `CheckRevocation`，或
   `CheckRevocationStatus`（`good` / `unchecked`（soft-fail）/ `skipped`（没有 hook）+ 错误）。对于 QUALIFIED
   的不可否认性，由 RP 配置。现成的 hook：`eid.NewOCSPChecker(eid.OCSPOptions{})`——证书 AIA 中的 OCSP
  （revoked/unknown → revoked；无响应 → unknown，由模式决定）。若要用其他 checker/模式做一次性检查：`CheckRevocationWith`。
   `OCSPOptions`（v0.5.2+）：`CacheTTL`（good 的缓存 = min(CacheTTL, NextUpdate−现在)；默认 5 分钟，负值 = 不缓存）；
   `Observe func(eid.OCSPObservation)`——每次检查（即使命中缓存）都会提供 `Status`、`Responder` URL、`Duration`、`Cached`、`Err`
  （不含 PII）——用于指标/审计。无响应时 checker 返回 `RevocationUnknown` + `*eid.OCSPError`（`Kind`：`no_responder`、
   `no_issuer`、`timeout`、`network`、`http_status`（+`HTTPStatus`）、`responder_status`、`parse`、`signature`、`invalid`；
   `errors.Is(err, eid.ErrOCSPNoAnswer)`）；`CheckRevocationWith` 按模式处理该 unknown——soft →
   `unchecked`、nil（原因见 `Observe`）；hard → `*ValidationError`（`Cause` = `*OCSPError`）。接受由颁发者签发、
   并嵌入响应中的 `id-kp-OCSPSigning` responder（RFC 6960 §4.2.2.2，ocsp.eidmongolia.mn 的“eID OCSP Responder”）
  （使用真实响应测试：`testdata/ocsp-eid-delegated.der`）；颁发者自己签名并嵌入自身证书的响应
  同样接受（自 v0.6.0 起；RFC 6960 §4.2.2.2），并用颁发者的密钥验证。
6. **颁发者与用途（v0.6.0 起的默认值）：** 若 `AllowedIssuerSKIs` 为空，则为 `[]string{eid.CitizenIssuingCASKI}`
  （配置了 TrustAnchorsPEM 时）——只接受公民 Issuing CA（04）的证书（同一 root 之下组织的
   05 等会被拦截；关闭方式：`AllowAnyIssuer: true`）；用途默认会被检查——auth → KU digitalSignature +
   EKU clientAuth，sign → KU nonRepudiation（CA 的 profile）：认证（PIN1）密钥所产生的签名不符合 `ValidateSign` 的要求
  （关闭方式：`SkipKeyUsageCheck: true`，不推荐；`CheckKeyUsage` 已弃用，不再生效）。`SchemeName`——
   CA 的 `acsp_scheme_name`（默认 `smart-id`）。

任何一步失败都会返回 `*eid.ValidationError`——**不要信任**该响应。错误文本中不会包含公民的姓名、PNOMN、注册号
（证书以序列号表示，路径为 `/etsi/…`）——可以直接写入日志。

## 5. 错误类型（`errors.As`）

| 错误 | 含义 |
|---|---|
| `*eid.AuthenticationError` | 401——API secret 错误/缺失；若为 CA 的 JSON 则有 `.Code`/`.Message`，若为 proxy 的则为空（`.Body`、`.Header`） |
| `*eid.ForbiddenError` | 403——IP allowlist / mTLS / RP 的权限；`OnBehalfOf` 被拒绝时有 `.Code` |
| `eid.ErrNoSigningCertificate` / `ErrCertChoiceInvalid` / `ErrRequestInvalid` | `errors.Is`——`*eid.APIError` 的 `Code`（409 `NO_SIGNING_CERTIFICATE`、409 `CERT_CHOICE_INVALID`、400 `REQUEST_INVALID`） |
| `*eid.ShareError` | `Share` 的 4xx/5xx（401/403 除外）——`.Code`、`.Reason`（422）、`.Sent`/`.Failed`/`.Recipients`（502）；`Unwrap` → `*eid.APIError` |
| `*eid.APIError` | 其他 HTTP 错误（`.Status`、`.Body`、`.Code`、`.RetryAfter`、`.Header`、`.Retryable()`——如 404 `ORG_NOT_FOUND`） |
| `*eid.ResponseTooLargeError` | 响应超过 SDK 限制（JSON 4 MiB）——`.Op`、`.Limit` |
| `*eid.NetworkError` | 网络 / 超时（`.Timeout`，`Unwrap` → `context.DeadlineExceeded` 等）；`.Op` 中公民的号码会被替换为 `…` |
| `*eid.SessionFailedError` | endResult ≠ OK（`TIMEOUT`、`USER_REFUSED…`）——`.EndResult` |
| `*eid.ValidationError` | 证书链 / 签名 / 级别 / 流程检查失败 |
| `*eid.DeviceLinkError` | 无法生成 device link（输入格式错误） |

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

## 7. 客户端 PAdES (`pades`)

PDF **不会发送到 eID 的任何服务器**（Smart-ID + DigiDoc 模式）：CA 只对 32 字节的 hash（DTBS）签名，PDF 的所有
工作（验证 QR 页、placeholder、signedAttrs、CMS、RFC 3161、OCSP/CRL、DSS、自身校验）都由本
库完成。Profile `pades-client/1` 源自 CA 的服务器端写入器（verify 页——全新的极简 writer，
运行时不压缩）；相同输入 → 相同字节。

```go
import "github.com/gerege-systems/eid-mongolia-sdk-go/pades"

// 1. 证书（certificate-choice）——在计算 hash 之前就需要，用于 signedAttrs 中的 signingCertificateV2。
cc, err := c.Sign.CertificateChoiceByEtsi(ctx, "PNOMN-12345678", nil)
r, err := c.Session.WaitForResult(ctx, cc.SessionID, nil)
signer, err := c.Validator.ValidateCertificateChoice(r, cc.SessionID)
// 2.（以组织名义签名时）CA 计算出的声明角色——原样传递。
reps, err := c.Organization.GetRepresentations(ctx, "PNOMN-12345678")
claimedRole := reps.Representations[0].ClaimedRole // OrgEtsi == onBehalfOf 的那一行
// 3. Prepare——PDF 保留在您的服务器上；首个 eID 签名带 QR 页（mn，Lang: "en"）。
p, err := pades.Prepare(pdfBytes, pades.PrepareOptions{SignerCert: signer.Certificate.Raw, VerifyPage: true,
	FileName: "合同第12号.pdf", ClaimedRole: claimedRole, Reason: "代表 Test 有限责任公司"})
// 4. 必须让恰好那台设备对 DTBS 签名。DigestForSigner / DeviceLinkForSigner 的默认算法 =
//    sha256WithRSAEncryption (PKCS#1 v1.5)——CMS 必须使用（Complete 会拒绝 DigestByEtsi 的默认 rsassa-pss，
//    返回 REQUEST_INVALID）。
s, err := c.Sign.DigestForSigner(ctx, signer, base64.StdEncoding.EncodeToString(p.DTBS), interactions,
	&eid.SignOptions{OnBehalfOf: "NTRMN-6235972"})
res, err := c.Session.WaitForResult(ctx, s.SessionID, nil)
_, err = c.Validator.ValidateSign(res, s.Sign.Digest, s.Sign.HashAlgorithm, eid.ValidateSignOptions{
	ExpectedAlgorithm: s.Sign.SignatureAlgorithm, ExpectedCertificate: signer.Certificate, ExpectedFlowType: eid.FlowNotification})
sig, _ := base64.StdEncoding.DecodeString(res.SignatureValueB64)
// 5. Complete——TSA https://tsa.timeserver.mn/、OCSP/CRL（AIA/CDP）、DSS、自身校验。
done, err := pades.Complete(ctx, p.State, sig, pades.CompleteOptions{})
// OCSP/CRL 临时失败时 SDK 会自行重试 2 次（约 1 s、约 3 s + 抖动；不会再次询问 PIN）——CompleteOptions.LTVRetries。
if pades.ErrorCode(err) == pades.CodeTSAUnavailable { /* p.State 保持不变——可再次尝试 */ }
// 6. 在 CA 登记（docID、/verify）——必须。Medium 为 "" 时由 SessionID 推断（phone ⇔ sessionID）；带 ClaimedRole 的
// 签名若没有 OnBehalfOf，则返回 REQUEST_INVALID（在到达 CA 之前）。
reg, err := pades.Registration(done, pades.RegistrationOptions{Medium: eid.PDFMediumPhone, SessionID: s.SessionID,
	OnBehalfOf: "NTRMN-6235972"})
_, err = c.PDF.RegisterSignature(ctx, reg) // POST /pdf/signatures
// done.PDF — PAdES-BASELINE-LT
rep, err := pades.ValidatePDF(ctx, done.PDF, pades.ValidateOptions{}) // 与 CA 的 /v3/validate/pdf 相同的报告（§7.2）
```

完整的、由编译器检查的版本：`pades/example_test.go`（`Example`）。

- `signature`：RSA PKCS#1 v1.5、ECDSA `r‖s`（P-256 为 64 / P-384 为 96 字节）或 DER——按证书密钥自动识别；
  RSASSA-PSS → `SIGNATURE_INVALID`（“需要 PKCS#1 v1.5”；与 TS / .NET / Swift / Kotlin 代码相同）。
- `RegisterSignature`——`POST /pdf/signatures`，请求体与 CA 的 `PDFSignatureRegisterRequest` 完全一致（不发送
  `hasPage`；`signerEtsi` = 证书的 SERIALNUMBER）。首个签名要被登记，必须带有 verify 页。
  `Created`——`true` 为 201（新建），`false` 为 200（相同请求体的重复提交）。若之前的签名由 CA 组装（模式 A），通过 `Registration` 的
  `PriorSignatures`（CMS + `sha256(doc[0 : ByteRange[2]+ByteRange[3]])` 的配对），在收到 409
  `PRIOR_MISMATCH` 后 SDK 会自行按 revision 对齐（若您手动设置了 `PriorRevisionSHA256` 则不会尝试）。
- 信任锚是内置的 Mongolian National Root CA（01）；02–05 是内置的中间证书链（若未提供 `Chain`，则按
  签名人的颁发者构建）。对于测试 PKI，使用 `CompleteOptions.Roots` / `VerifyOptions.Roots`（DER）。
- 错误为 `*pades.Error`（`Code`）：`PDF_INVALID`、`PDF_ENCRYPTED`、`PDF_LOCKED`（DocMDP P=1）、`PDF_TOO_LARGE`
 （输入 > 10 223 616 字节）、`PDF_TOO_MANY_SIGNATURES`、`PDF_PRIOR_SIGNATURE_INVALID`、`PDF_FOREIGN_SIGNATURE`（之前
  签名的签名人不是来自 eID 的 04/05，或 SubFilter 不是 CAdES——[PRECHECKS.md](pades/PRECHECKS.md)）、`SIGNER_INVALID`、`REQUEST_INVALID`、`SIGNATURE_INVALID`、`TSA_UNAVAILABLE`、
  `LTV_UNAVAILABLE`、`SELF_VALIDATION_FAILED`、`PLACEHOLDER_OVERFLOW`、`STATE_INVALID`。
- **LTV 重试（v0.6.0）**——若收集 OCSP/CRL（DSS）失败（`LTV_UNAVAILABLE` 的情形，例如国家 CRL 镜像暂时返回 404），
  `Complete` 会使用相同的 state、签名和 TSA 时间戳自行重试：`CompleteOptions.LTVRetries`（`*int`；nil =
  `pades.DefaultLTVRetries` 2——共 3 次尝试，等待约 1 s、约 3 s + 0–25% 抖动；`0`——关闭；超出 0–10 →
  `REQUEST_INVALID`）。全部失败则返回 `LTV_UNAVAILABLE`；若 `ctx` 被取消，等待会中断，并返回包装了 `context.Canceled` 的 `LTV_UNAVAILABLE`。
  与 TS SDK 0.18.3 的 `ltvRetries` 相同——TS 和 Go 都有 LTV 重试。
- **LTV 吊销顺序（v0.28.1）**——`Complete` 按证书的角色：
  - 链中的第一个（end-entity：公民、TSA）证书——**先 OCSP**（10 s 超时，`thisUpdate > genTime`），同时也
    获取 CRL，两者都写入 DSS；若没有有效的 OCSP 响应，则用 CRL；
  - CA 证书（链中的其余部分）——**先 CRL**；若已获得有效的 CRL，则绝不会访问该证书的 OCSP responder
    （DSS 中只有 CRL）；仅在没有有效 CRL 时才用 OCSP（10 s 超时）。

  每个证书的获取并发进行；DSS 按证书链顺序。接受规则、“revoked” = 硬错误、fail-closed
  均未改变。`ValidatePDF`（仅对 04/05 签发的证书做在线检查）未改变。
- 对已签名的文档再次签名时不会新增页面；docID 从第一页的 `/verify/<uuid>` 链接中读取。
- `VerifyPagePosition: pades.VerifyPageFirst`（v0.15.0+）——该页放在文档的**开头**（第 1 页）；默认为
  `pades.VerifyPageLast`（在末尾，与之前字节一致）。`Appearance.Page`、`SuggestPlacement` 和 `Placement.Page` 都
  按输入 PDF 的页码计算（新增的页不计入）。PAGE_SPEC §8a，PLACEMENT_SPEC §1b。

### 7.1. 可见签名（可选）

默认不可见（与之前字节一致）。若 RP 在页面上给出一个矩形，widget 会绘制一个外观，包含姓名、（onBehalfOf 时的）角色、
“eID Mongolia-аар зурсан” / “Signed with eID Mongolia”、`YYYY-MM-DD HH:MM (+08)` 日期，以及每个签名各自的 QR
（`https://ca.eidmongolia.mn/verify/<docID>/<revIndex>`）：

```go
p, err := pades.Prepare(pdfBytes, pades.PrepareOptions{SignerCert: cert, VerifyPage: true, FileName: "合同.pdf",
	Appearance: &pades.Appearance{Page: 0, X: 36, Y: 36, Width: 220, Height: 64}}) // Page 0 = 最后一页，而不是输入文档中的 eID verify 页
```

- 坐标——pt，自页面 CropBox（若无则用 MediaBox）**屏幕上所见**（应用 `/Rotate` 之后）的左下
  角起算；支持 `/Rotate` 的 0/90/180/270（外观保持直立）。精确到 0.01 pt。
- `Page` 是传给 Prepare 的文档的页码（从 1 开始；显式指定的页码不会跳过任何页）。0 = 最后一页，而**不是** eID verify 页——
  本次 Prepare 新增的以及之前 revision 所新增的 verify 页不计入（v0.12.0+，PLACEMENT_SPEC §1a）。
- `X, Y` 是请求的位置：若该处存在页面内容（文字、表格线、图片、之前的签名），
  外观会移到空白区域——先到镜像列（右下 → 左下），然后每次上移 12 pt。
  结果：`Prepared.Placement`（`Status`：`requested` | `moved` | `overlap`——没有空白区域，仍在请求的位置
  | `unscanned`——在限制内无法读取该页）。详情：[PLACEMENT_SPEC.md](pades/PLACEMENT_SPEC.md)。
- `Exact: true`（v0.14.0+）——由公民自行选择的位置：绝不会移动，准确绘制在 `Page/X/Y/Width/Height`
 （超出页面则返回 `REQUEST_INVALID`）；若与内容重叠，则 `Status` = `overlap`。PLACEMENT_SPEC §6a。
- `pades.SuggestPlacement(pdf, appearance)`（v0.14.0+）——在没有签名、证书和网络的情况下给出 Prepare 将选择的位置
 （`Page` 已解析，`X/Y/Width/Height/Status`）以及 `PageWidth/PageHeight`、`PageCount`、`Pages[]`（每页的
  可见尺寸，pt）——在 UI 中展示默认位置，用户移动之后，通过 `Exact: true` 传给 Prepare。
  坐标：自可见的左下角起算（UI 的左上 `top` → `y = PageHeight − top − Height`）。PLACEMENT_SPEC §6b。
- 高度 ≥ 45 pt（QR 模块 ≥ 1 pt）、文字放不下（姓名最多缩小到 7 pt，其余缩小到 5 pt）、超出页面、页面
  不存在、无法写入 `/Name` 的姓名、docID 未知 → `REQUEST_INVALID`。日期为声明的 SigningTime（prepare 时并不
  知道 TSA 的时间）。
- `Verify` 报告：`visible`（该签名可见）、`visible_later_signature`。验证器只接受恰好这种形态（会重新生成 widget +
  `/AP` 并在字节级别比对）。详情：[APPEARANCE_SPEC.md](pades/APPEARANCE_SPEC.md)。

### 7.2. 验证已签名的 PDF——`pades.ValidatePDF`（v0.7.0）

RP 在自己的后端上（无需将文件发往任何地方），使用 CA 公共验证器（`/v3/validate/pdf`）的代码进行验证——
报告与 CA 的 JSON 相同（snake_case）。浏览器中的规则相同：TS SDK 的 `validatePdf`（`@gerege-systems/eid-mongolia-sdk/validate`）。

```go
rep, err := pades.ValidatePDF(ctx, pdfBytes, pades.ValidateOptions{}) // 默认：内置的国家 Root CA，在线吊销检查
switch pades.ErrorCode(err) {
case pades.CodePDFNoSignature, pades.CodePDFInvalid, pades.CodePDFTooLarge, pades.CodePDFTooManySignatures: // 4xx
case pades.CodePDFEncrypted: // v0.7.1：已加密（/Encrypt）——请告知用户移除保护后重新提交
case pades.CodeRequestInvalid: // ValidateOptions.Roots/Intermediates/Issuers 无法解析
}
if rep.Indication == pades.Valid { /* 所有签名均有效 */ }
for _, s := range rep.Signatures {
	_ = s.SignerName           // 来自证书（claimed_name——写在 PDF 中，未经验证）
	_ = s.SigningTime          // 受信任的 RFC 3161 时间
	_ = s.SignatureLevel       // PAdES-BASELINE-B | -T | -LT
	_ = s.CertificateLevel     // QUALIFIED | QSCD | ADVANCED (qcStatements)
	_ = s.Problems             // integrity_failed, untrusted_chain, revoked, modified_after_signing …
}
```

- 检查项：ByteRange（间隙恰好是该 `/Contents`）和 messageDigest、CMS 签名、signingCertificateV2、证书链
 （国家 01 → 02/03 → 04/05）、KU/EKU（公民 SIGN、组织印章、doc-signer；AUTH/TLS → `wrong_key_usage`）、
  有效期（按时间戳的时间）、RFC 3161 令牌（TSA 证书链、critical timeStamping EKU）、签名之后的每个 revision 都只能是
  eID 的签名/LTV 所允许的形态（其他 → `modified_after_signing`）、可见签名（APPEARANCE_SPEC
  §5）、LTV 的完整性（`ltv`）。
- 吊销（针对由 eID 的 04/05 签发的证书）：在线——AIA OCSP，否则 CDP CRL（由颁发者签名）；无响应
  或 `Offline: true` 时使用文档的 DSS。两者都没有 → `revocation_unavailable`（indeterminate）。在时间戳之后
  被吊销 → `revoked_after_signing`（仍然有效）。网络上只会发送证书序列号（OCSP），不会发送文档。
- 吊销证据规则（v0.7.2）：OCSP 必须针对**该**证书（CertID = 链中颁发者的名称/密钥 hash +
  序列号），CRL 必须属于颁发者（名称、AKI、签名）。“good”在检查时必须是新鲜的：thisUpdate 不在未来
 （5 分钟容差），nextUpdate 未过期，且 thisUpdate ≤ 24 小时前，或 thisUpdate…nextUpdate 覆盖检查时间
 （检查时间 = 受信任时间戳的时间，否则为 `Time`/当前时间）。否则不予采信 → `revocation_unavailable`。
  由颁发者签名的“revoked”证据（OCSP 或 CRL，在线或 DSS）始终压过“good”。
- **不受信任的 PDF。** `Prepare`/`ValidatePDF`/`Verify`/`Complete` 在解析之前会检查数组/字典的嵌套
 （`> 256` → 在 `Prepare`/`ValidatePDF`/`Verify` 中为 `PDF_INVALID`，在 `Complete` 中为 `STATE_INVALID`；两者均可用
  `errors.Is(err, pades.ErrPDFStructure)` 判断）（v0.7.2；此前，一份约 2 MB 的 `[[[…` 文档
  会以 `fatal error: stack overflow` 使整个进程崩溃）。这只是一层防护——请将来自外部的
  PDF 视为不受信任的输入：限制大小（≤ 10 MiB），为每个请求设置超时，并尽可能在单独的
  进程/容器（带 CPU/内存限制）中解析。
- `key_medium`：SDK 中仅来自证书——带 qcStatements 的公民 SIGN → `phone`，其他为 `unknown`。CA（`POST
  /v3/validate/pdf`）根据自己的登记确定 `token`，以及 eID 签发的组织印章的 `server_software` / `server_hsm`
 （密钥位于服务器一侧；这并不声明其为 QSCD）——取值为 `pades.KeyMediumToken` | `KeyMediumPhone` |
  `KeyMediumServerSoftware` | `KeyMediumServerHSM` | `KeyMediumUnknown`（v0.27.0）。`session_id`、`doc_id`、`on_behalf_of_*`、`stamp_lookup` 来自 CA 的登记——SDK 中没有。
- 已加密的 PDF（`/Encrypt`——RC4、AES-128、AES-256，即使用户密码为空）→ `PDF_ENCRYPTED`（v0.7.1；
  此前为 `PDF_INVALID`，而且对于 RC4，会将正确的签名误判为 `malformed_signature` 而视为无效）。TS SDK 与 CA 相同。
- `Verify`（v0.5）= `ValidatePDF` + `Offline: true`（已弃用；对没有签名的文档，会像以前一样返回空的 `valid`）。
- Conformance：`pades/testdata/validate/`——Go、TS 和 CA 使用同一套测试，得到相同的报告。

Go 是**参考实现**（带有完整的验证器 `Verify`，用于后端）；TS / Swift / Kotlin / C# 的 native SDK 则 1:1 复现
签名路径（[PROFILE.md](pades/PROFILE.md)、[PAGE_SPEC.md](pades/PAGE_SPEC.md)、[PRECHECKS.md](pades/PRECHECKS.md)、
[WIRE.md](pades/WIRE.md)、[APPEARANCE_SPEC.md](pades/APPEARANCE_SPEC.md)、[PLACEMENT_SPEC.md](pades/PLACEMENT_SPEC.md)），并产出字节一致的 golden。运行时不做压缩（xref/DSS/页面）——为了
跨语言的字节一致。

Golden vector：`pades/testdata/golden/`（README，tag `pades-golden-v6`）——每个 native SDK 的 CI 都会比对；本仓库的 CI
还会用 qpdf（`--check`）和 pyHanko（INTACT/VALID/TRUSTED，由 DSS 得到 LT，是否可见）独立检查每个
输出。

### 7.3. 使用组织印章为 PDF 盖章——`pades.SealPDF`（v0.24.0）

```go
done, err := pades.SealPDF(ctx, c.Seal, "NTRMN-6235972", pdfBytes, pades.SealOptions{Reason: "发票"})
// done.PDF — PAdES-BASELINE-LT, 带有组织印章
```

流程：印章证书 → `Prepare`（SignerCert = 印章证书）→ 通过 `POST /seal/{orgEtsi}` 对 32 字节 DTBS 盖章（SHA-256）
→ `Complete`。PDF 不会发送到 eID。**必须包含 RFC 3161 时间戳**（eID TSA，`SealOptions.Complete.TSAURL`）：
若无法连接 TSA，则返回 `TSA_UNAVAILABLE`，绝不返回没有印章/时间戳的文件；OCSP/CRL + DSS → B-LT，然后
进行 self-validation。不添加验证页。在 `/verify/{docID}` 登记印章——见下文“在 CA 登记印章”。

**可见图章（默认，Unreleased）。** 印章会在文档最后一页（不是 eID verify 页）留下组织印章的图章：
组织名称、“eID Mongolia-аар тамгалсан” / “Sealed with eID Mongolia”、盖章时间——没有 QR、链接和角色
（`pades/APPEARANCE_SPEC.md` §6）。位置：220 × 64 pt，右下角（边距 36 pt；在小页面上会适配）；
若该处有内容，则按 PLACEMENT_SPEC 的规则移到空白位置，若没有空白位置，则留在右下角并压在内容之上
（`overlap`）。若图章放不进页面（例如页面极小），印章不可见，且 `done.Placement` = nil。
`SealOptions.Appearance`——自行指定位置（与公民的 `Appearance` 相同，`Exact` 也适用），`SealOptions.Invisible: true`——
之前不可见的输出（字节一致）。结果在 `done.Placement` 中。之前的签名（包括公民的可见签名）
仍然有效。**注意：** 早于本版本的验证器（CA 的 `/v3/validate/pdf`、TS SDK）不识别印章图章，
因此会将之前的签名报告为已被修改——在它们更新之前，请使用 `Invisible: true`。

**带 QR 的印章图章（Unreleased——仅限验证器）。** `pades/APPEARANCE_SPEC.md` §6.5：与公民图章相同的结构
（QR + `/verify/<docId>/<rev>`），带有印章的 label 且没有角色行——使没有 verify 页的印章文档（发票、
证明）可以被扫描验证。**本版本只让验证器（`pades.ValidatePDF`、`Complete` 的
self-validation）识别带 QR 的印章；写入方（`SealPDF`）默认仍输出不带 QR 的图章**（与 v0.30.0 字节一致）；带 QR 的图章为
`SealOptions.QR`（与印章登记一起——见下文“在 CA 登记印章”）。
不带 QR 的图章永远有效。另外，`Prepare` 的 docId（§6.6）：若没有 verify 页的文档中有带 QR（带 marker）的**印章**图章，
则取其 docId——对可见和**不可见**签名都适用（此前不可见签名取 `opts.docId` 或空），
若提供了不同的 `opts.docId`，则返回 `REQUEST_INVALID`。不会为已签名文档生成随机 docId：在不带 QR 的
印章之后，当公民做可见签名时，必须提供 `opts.docId`（由调用方自行登记），否则仍然
返回 `REQUEST_INVALID`，与之前相同。

验证器（`pades.ValidatePDF`、CA 的
`/v3/validate/pdf`）会将此签名归类为 `certificate.usage = "seal"`——请向用户显示为“组织印章”。
错误：`CodeSignerInvalid`（证书不是 e-Seal，或在盖章期间证书已更换——重试）、
`CodeSignatureInvalid`、`CodeTSAUnavailable`/`CodeLTVUnavailable`（临时性），RP-API 的错误（`*ForbiddenError`、`*APIError`）
保持不变——若盖章已关闭，则为 503 `eid.ErrSealServiceDisabled`（§3.10；`SealPDF` 不会重试，也绝不会返回未盖章的文件）。`pades.Sealer` 接口（`*eid.SealService` 实现了它）——可在测试中替换。

#### 在 CA 登记印章——`c.Seal.RegisterSealedPDF`、带 QR 的图章（Unreleased，CA V158）

```go
done, err := pades.SealPDF(ctx, c.Seal, org, pdfBytes, pades.SealOptions{QR: true, FileName: "Invoice.pdf"})
// done.PDF — 带 QR 的图章（/verify/<docId>/<revIndex>）；done.SealRegistration — 现成的登记请求体
reg, err := c.Seal.RegisterSealedPDF(ctx, org, *done.SealRegistration)
// reg.VerifyURL — https://ca.eidmongolia.mn/verify/<docID>；reg.Created：201 为 true，相同请求体的重放 200 为 false
```

- `POST /seal/{orgEtsi}/registrations`（`SEAL:<orgEtsi>`）：在 `/verify/{docID}` 上以组织行（不含个人姓名）显示印章——
  公民 `PDF.RegisterSignature` 的印章版本。请求体（`eid.SealRegistration`）：`docID, revIndex, cms, fileName?, inSha256,
  sigRevSha256, outSha256, priorCmsSha256?, priorRevisionSha256?`——**不含** `medium`、`sessionID`、`onBehalfOf`、
  `signerEtsi`、`pageSha256`。`SealRegistration.Validate()` 离线检查 CA 的格式规则。条件：由**本 RP** 请求的盖章、
  盖章后 **7 天内**、每个 RP 每 10 分钟 600 次。
- `SealOptions.QR`——带 QR 的印章图章（APPEARANCE_SPEC §6.5）；盖章时通过 `SealForDocument` 预留 `{docId, revIndex}`
  （`pades.DocumentSealer`——`*eid.SealService` 实现了它）。QR 意味着承诺登记——务必登记。默认（QR 为 false）——不带 QR
  的图章，与之前字节一致；也可以登记。`SealOptions.DocID`——对没有 verify 页 / 带 QR 印章图章的已签名文档是必需的
  （否则 `done.SealRegistration` 为 nil；QR 时为 `REQUEST_INVALID`）。
- 遇到 409 `PRIOR_MISMATCH` 时，按与公民登记相同的组合用 `PriorSignatures` 自动重试。

| 代码（`eid.SealRegisterErrorCodes`） | HTTP | 含义 |
|---|---|---|
| `REQUEST_INVALID` / `CMS_INVALID` / `SIGNATURE_INVALID` / `TIMESTAMP_INVALID` | 400 | 格式 / CMS 配置 / 签名 / TST（盖章时间 −5 分钟…+1 小时） |
| `REQUEST_TOO_LARGE` | 413 | 请求体 > 64 KiB |
| `SEAL_NOT_FOUND`（`eid.CodeSealNotFound`） | 409 | 未找到本 RP 对该 digest 的盖章，或已超过 7 天 |
| `SEAL_DOC_MISMATCH`（`eid.CodeSealDocMismatch`） | 409 | 预留的 docId/revIndex 与登记不一致 |
| `DOC_ID_RESERVED`（`eid.CodeDocIDReserved`） | 409 | 另一个未登记的 QR 印章在更低位置预留了该 docID |
| `SIGNER_MISMATCH` / `SIGNER_CERT_INVALID` | 409 | 证书的组织与 URL 不符 / 证书无效 |
| `DOC_ID_CONFLICT` / `PRIOR_MISMATCH` / `REGISTRY_CONFLICT` | 409 | 与公民登记相同的链规则 |
| `RATE_LIMITED` / `STATE_UNAVAILABLE` | 429 / 503 | `Retryable()`、`RetryAfter` |
| — | 403 | `*ForbiddenError`——没有 `SEAL:<orgEtsi>` 权限 |

## 开发

```bash
go vet ./... && go test -race ./...
go test ./pades -run Golden -update                                              # 重写 golden 文件（仅在 profile 变化时）
```

测试：CA 服务器的 device link golden 向量（`testdata/devicelink_golden.json`，与 TS SDK 为同一文件）、Smart-ID
ACSP_V2 向量、RFC 7636 PKCE 向量、真实的公共 CA 证书。

### 合约检查

SDK 调用的每一个 RP-API 路径（`routes.go`）都必须出现在线上 [`/.well-known/eid`](https://rp.eidmongolia.mn/.well-known/eid) 的
`endpoints` 中。Discovery 中存在但 SDK 未覆盖的路径只给出 WARN（不算失败）。由于需要网络，它不包含在普通的 `go test` 中：

```bash
go test -count=1 -v -tags contract -run Contract ./...
```

CI：`.github/workflows/contract.yml`——PR、`main` push、每天 00:00 UTC、手动触发。

许可证：MIT。
