// Package eidlogin — «eID-ээр нэвтрэх» товчны RP backend (net/http), RP-API v3 device link + push дээр.
// Хөтчийн товч нь TS SDK-ийн `@gerege-systems/eid-mongolia-sdk/button` (`<eid-login-button>`); хариуны хэлбэр TS-ийн
// createEidLogin-тэй ижил.
//
//	POST {base}/start   {"mode":"qr"} | {"mode":"push","idCode":"УБ12345678"} → {mode, vc, qr?, expiresIn}
//	GET  {base}/start?mode=web2app                     → 302 → eID апп (Web2App холбоос)
//	GET  {base}/status                                 → PENDING (+шинэ QR) | WAIT_CALLBACK | OK | FAILED | EXPIRED
//	GET  {base}/callback?sessionId&userChallengeVerifier → Web2App буцалт: шалгаад 303
//
// eID сервер Web2App callback-ийн замыг үргэлж /auth/eid/callback болгож нормчилдог тул {base} = /auth/eid:
//
//	h, err := eidlogin.New(eidlogin.Config{Client: c, CallbackURL: "https://bank.mn/auth/eid/callback", OnSuccess: login})
//	mux.Handle("/auth/eid/", h)
//
// Төлөв (sessionToken, sessionSecret, rpChallenge, ACSP) серверт (Store); хөтчид зөвхөн HttpOnly cookie
// (<sessionId>.<binding>) — status/callback зөвхөн session-ийг эхлүүлсэн хөтчид хариулна (login CSRF, relay хаалт).
// Иргэн зөвхөн Validator.ValidateAuth (гинж + ACSP_V2 + flowType + Web2App-д userChallengeVerifier)-ийн дараа OnSuccess-д.
package eidlogin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// Mode — нэвтрэлтийн горим.
type Mode string

const (
	ModeQR      Mode = "qr"      // desktop QR
	ModePush    Mode = "push"    // регистрийн дугаараар утас руу мэдэгдэл
	ModeWeb2App Mode = "web2app" // утасны хөтчөөс eID апп руу
)

// CallbackPath — eID серверийн нормчилдог Web2App буцах зам.
const CallbackPath = "/auth/eid/callback"

// Identity — баталгаажсан иргэн (OnSuccess-д).
type Identity struct {
	// SessionID — RP-API session-ий id: аудит, эсвэл энэ нэвтрэлтийг дараагийн алхамтай (гарын үсэг г.м.) холбоход.
	SessionID string
	// ETSI — гэрчилгээний SERIALNUMBER (PNOMN-<иргэний дугаар>). Хэрэглэгчийг ҮҮГЭЭР таньна (нэрээр биш).
	ETSI string
	// CivilID — PNOMN-гүй иргэний дугаар; ETSI өөр хэлбэртэй бол "".
	CivilID string
	// GivenName, Surname — гэрчилгээний нэр (латин).
	GivenName, Surname string
	Country            string
	// DocumentNumber — иргэний баримтын дугаар; Client.Sign-ийн *ByDocument-аар ижил төхөөрөмж рүү гарын үсэг.
	DocumentNumber   string
	CertificateLevel string
	// Certificate — нэвтрэлтийн гэрчилгээ (ValidateAuth-аар гинж шалгагдсан).
	Certificate *x509.Certificate
	// FlowType — гарын үсэг зурагдсан урсгал: QR | Notification | Web2App.
	FlowType eid.FlowType
	// Person — session-ий person блок (кирилл нэр г.м.), гэрчилгээтэй таарсан үед л; эс бөгөөс nil.
	Person *eid.Person
}

// Link — QR/Web2App холбоос угсрах материал. Secret нь ЗӨВХӨН серверт.
type Link struct {
	Base       string    `json:"base"`
	Token      string    `json:"token"`
	Secret     string    `json:"secret"`
	ReceivedAt time.Time `json:"receivedAt"`
	Lang       string    `json:"lang"`
}

// Tx — серверт хадгалах нэвтрэлтийн төлөв (JSON-д хувирна).
type Tx struct {
	SessionID string `json:"sessionId"`
	// BindingHash — cookie-ийн binding-ийн SHA-256 (hex); түүхий утга хөтчид л.
	BindingHash string           `json:"bindingHash"`
	Mode        Mode             `json:"mode"`
	ExpiresAt   time.Time        `json:"expiresAt"`
	VC          string           `json:"vc"`
	ACSP        *eid.ACSPContext `json:"acsp"`
	Link        *Link            `json:"link,omitempty"`
}

// Store — төлөвийн сан. Анхдагч NewMemoryStore (нэг процесс); олон instance бол Redis г.м.
type Store interface {
	// Get — олдохгүй / хугацаа дууссан бол (nil, nil).
	Get(ctx context.Context, sessionID string) (*Tx, error)
	Set(ctx context.Context, tx *Tx, ttl time.Duration) error
	// Delete — байсан бол true. Амжилтыг нэг л удаа гаргахад ашиглана (атомар байх ёстой — Redis DEL).
	Delete(ctx context.Context, sessionID string) (bool, error)
}

type memEntry struct {
	tx  Tx
	exp time.Time
}

type memoryStore struct {
	mu sync.Mutex
	m  map[string]memEntry
}

// NewMemoryStore — нэг процессын санах ойн сан (TTL-тэй).
func NewMemoryStore() Store { return &memoryStore{m: map[string]memEntry{}} }

func (s *memoryStore) Get(_ context.Context, k string) (*Tx, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	if !ok {
		return nil, nil
	}
	if !time.Now().Before(e.exp) {
		delete(s.m, k)
		return nil, nil
	}
	tx := e.tx
	return &tx, nil
}

func (s *memoryStore) Set(_ context.Context, tx *Tx, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.m) > 1000 {
		for k, e := range s.m {
			if !now.Before(e.exp) {
				delete(s.m, k)
			}
		}
	}
	s.m[tx.SessionID] = memEntry{tx: *tx, exp: now.Add(ttl)}
	return nil
}

func (s *memoryStore) Delete(_ context.Context, k string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[k]
	delete(s.m, k)
	return ok, nil
}

// Success — OnSuccess-ийн хариу.
type Success struct {
	// Redirect — нэвтэрсний дараах хуудас. Callback (Web2App)-д хоосон бол Config.SuccessRedirect.
	Redirect string
	// Data — QR/push-ийн status хариунд "data" болж хөтчид очно (JSON). Нууц бүү оруул.
	Data any
}

// Config — Handler-ийн тохиргоо.
type Config struct {
	Client *eid.Client
	// OnSuccess — RP-ийн session-ийг ЭНД үүсгэнэ (иргэн баталгаажсан): хэрэглэгчийг id.ETSI-ээр таньж, ШИНЭ session
	// (session fixation) үүсгээд http.SetCookie(w, …). Алдаа буцаавал 500 / failure redirect.
	OnSuccess func(w http.ResponseWriter, r *http.Request, id *Identity) (*Success, error)
	// CallbackURL — Web2App буцах https URL (host нь RP-ийн callbackHosts-д, зам нь ЗААВАЛ /auth/eid/callback).
	// Хоосон бол утасны урсгал (mode=web2app) 400 — QR/push л ажиллана.
	CallbackURL string
	// SuccessRedirect — callback амжилттай (OnSuccess Redirect өгөөгүй) бол. Анхдагч "/".
	SuccessRedirect string
	// FailureRedirect — callback амжилтгүй бол, ?eid_error=<код> нэмэгдэнэ. Анхдагч "/".
	FailureRedirect string
	// DisplayText — утсанд харагдах текст (≤60). Анхдагч «<RPName>-д нэвтрэх».
	DisplayText      string
	CertificateLevel eid.CertificateLevel
	// TTL — нэвтрэлтийн хугацаа (анхдагч 2 мин). Poll — status-ийн нэг дуудлагад eID-ийг хүлээх (анхдагч 1 с).
	TTL, Poll time.Duration
	Store     Store
	// CookieName (анхдагч eid_login), CookiePath (анхдагч /), CookieDomain. InsecureCookie — зөвхөн http dev-д.
	CookieName, CookiePath, CookieDomain string
	InsecureCookie                       bool
	// RateLimit — "start:<ip>" (ClientIP өгсөн бол) ба "push:<idCode>" түлхүүрээр; false → 429. Анхдагч: push-д нэг
	// дугаарт 60 секундэд 3 (санах ойд) — хохирогчийн утсыг мэдэгдлээр дарахаас (MFA fatigue).
	RateLimit func(ctx context.Context, key string) bool
	// ClientIP — "start:<ip>" хязгаарын клиент IP. Итгэмжит reverse proxy-ийн ард ForwardedClientIP(n), шууд
	// холбогддог бол RemoteAddrIP, эсвэл өөрийн функц. nil бол IP-ээр хязгаарлахгүй (New нэг удаа Warn бичнэ) — TS-ийн
	// createEidLogin-ий trustProxy / getClientIp-тэй ижил дүрэм.
	ClientIP func(*http.Request) string
	// Logger — дотоод алдаа (анхдагч slog.Default()). Иргэний мэдээлэл бичихгүй.
	Logger *slog.Logger
}

// Handler — /start, /status, /callback (замын сүүлийн хэсгээр). goroutine-safe.
type Handler struct {
	cfg          Config
	interactions []eid.Interaction
	log          *slog.Logger
	failURL      url.URL

	mu       sync.Mutex
	pushHits map[string][]time.Time
}

var (
	idRe      = regexp.MustCompile(`^(\p{L}{2}[0-9]{8}|[0-9]{8,14}|PNOMN-[0-9]{8,14})$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	bindingRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	civilRe   = regexp.MustCompile(`^PNOMN-([0-9]+)$`)
)

// ForwardedClientIP — итгэмжит reverse proxy-ийн ард Config.ClientIP: X-Forwarded-For-ийн БАРУУНААС hops дахь утга
// (hops = таны итгэмжит proxy-ийн тоо; nginx нэг бол 1), XFF байхгүй бол X-Real-IP. XFF-д hop дутвал "" (хуурамч
// header-ээр тойрохоос). Proxy-гүй үед бүү хэрэглэ — header-ийг клиент өөрөө илгээнэ. hops < 1 бол panic.
func ForwardedClientIP(hops int) func(*http.Request) string {
	if hops < 1 {
		panic("eidlogin: ForwardedClientIP hops >= 1 байх ёстой")
	}
	return func(r *http.Request) string {
		var xff []string
		for _, v := range r.Header.Values("X-Forwarded-For") {
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					xff = append(xff, p)
				}
			}
		}
		if len(xff) > 0 {
			if hops > len(xff) {
				return ""
			}
			return xff[len(xff)-hops]
		}
		return strings.TrimSpace(r.Header.Get("X-Real-IP"))
	}
}

// RemoteAddrIP — proxy-гүй (клиент шууд холбогддог) үед Config.ClientIP: r.RemoteAddr-ийн host.
func RemoteAddrIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// New — тохиргоог шалгаж Handler үүсгэнэ.
func New(cfg Config) (*Handler, error) {
	if cfg.Client == nil {
		return nil, errors.New("eidlogin: Client шаардлагатай")
	}
	if cfg.OnSuccess == nil {
		return nil, errors.New("eidlogin: OnSuccess шаардлагатай")
	}
	if cfg.CallbackURL != "" {
		u, err := url.Parse(cfg.CallbackURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != CallbackPath {
			return nil, fmt.Errorf("eidlogin: CallbackURL нь https://<таны host>%s байх ёстой", CallbackPath)
		}
	}
	if cfg.SuccessRedirect == "" {
		cfg.SuccessRedirect = "/"
	}
	if cfg.FailureRedirect == "" {
		cfg.FailureRedirect = "/"
	}
	failURL, err := url.Parse(cfg.FailureRedirect)
	if err != nil {
		return nil, fmt.Errorf("eidlogin: FailureRedirect: %w", err)
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 2 * time.Minute
	}
	if cfg.Poll <= 0 {
		cfg.Poll = time.Second
	}
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "eid_login"
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
	text := cfg.DisplayText
	if text == "" {
		text = cfg.Client.RPName() + "-д нэвтрэх"
	}
	text = truncateRunes(text, 60)
	h := &Handler{cfg: cfg, log: cfg.Logger, failURL: *failURL, pushHits: map[string][]time.Time{}}
	if h.log == nil {
		h.log = slog.Default()
	}
	if cfg.ClientIP == nil {
		h.log.Warn("eidlogin: Config.ClientIP алга — start:<ip> хязгаар ажиллахгүй; ForwardedClientIP(n) эсвэл RemoteAddrIP өг")
	}
	h.interactions = []eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: text}}
	if h.cfg.RateLimit == nil {
		h.cfg.RateLimit = h.defaultLimit
	}
	return h, nil
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func (h *Handler) defaultLimit(_ context.Context, key string) bool {
	if !strings.HasPrefix(key, "push:") {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if len(h.pushHits) > 10000 {
		h.pushHits = map[string][]time.Time{}
	}
	var hits []time.Time
	for _, t := range h.pushHits[key] {
		if now.Sub(t) < time.Minute {
			hits = append(hits, t)
		}
	}
	if len(hits) >= 3 {
		h.pushHits[key] = hits
		return false
	}
	h.pushHits[key] = append(hits, now)
	return true
}

// ServeHTTP — замын сүүлийн хэсгээр (start | status | callback) чиглүүлнэ.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch path.Base(strings.TrimRight(r.URL.Path, "/")) {
	case "start":
		h.Start(w, r)
	case "status":
		h.Status(w, r)
	case "callback":
		h.Callback(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func (h *Handler) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: h.cfg.CookieName, Value: value, Path: h.cfg.CookiePath, Domain: h.cfg.CookieDomain, MaxAge: maxAge,
		HttpOnly: true, Secure: !h.cfg.InsecureCookie, SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) clearCookie(w http.ResponseWriter) { h.setCookie(w, "", -1) }

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// loadTx — cookie → tx (binding таарсан, хугацаа дотор). Олдохгүй бол (nil, nil).
func (h *Handler) loadTx(r *http.Request) (*Tx, error) {
	c, err := r.Cookie(h.cfg.CookieName)
	if err != nil {
		return nil, nil
	}
	sid, binding, ok := strings.Cut(c.Value, ".")
	if !ok || !uuidRe.MatchString(sid) || !bindingRe.MatchString(binding) {
		return nil, nil
	}
	tx, err := h.cfg.Store.Get(r.Context(), sid)
	if err != nil || tx == nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(tx.BindingHash), []byte(sha256hex(binding))) != 1 {
		return nil, nil
	}
	if !time.Now().Before(tx.ExpiresAt) {
		if _, err := h.cfg.Store.Delete(r.Context(), sid); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return tx, nil
}

func (h *Handler) qrLink(tx *Tx) string {
	if tx.Mode != ModeQR || tx.Link == nil {
		return ""
	}
	link, err := eid.BuildDeviceLink(eid.DeviceLinkInput{
		DeviceLinkBase: tx.Link.Base, DeviceLinkType: eid.LinkQR, SessionToken: tx.Link.Token, SessionSecret: tx.Link.Secret,
		SessionType: eid.SessionAuth, Lang: tx.Link.Lang, ReceivedAt: tx.Link.ReceivedAt, RPChallenge: tx.ACSP.RPChallenge,
		RelyingPartyName: tx.ACSP.RelyingPartyName, Interactions: tx.ACSP.Interactions,
	})
	if err != nil {
		h.log.Error("eidlogin: QR холбоос", "err", err)
		return ""
	}
	return link
}

type startBody struct {
	Mode   Mode   `json:"mode"`
	IDCode string `json:"idCode"`
	Lang   string `json:"lang"`
}

// Start — POST {mode: qr|push} эсвэл GET ?mode=web2app.
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	// CSRF: cross-site хүсэлтээр session/push эхлүүлэхгүй. POST нь JSON (simple request биш → CORS preflight).
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "same-site", "none":
	default:
		errJSON(w, http.StatusForbidden, "cross_site")
		return
	}
	var b startBody
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("mode") != string(ModeWeb2App) {
			errJSON(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		b = startBody{Mode: ModeWeb2App, Lang: r.URL.Query().Get("lang")}
	case http.MethodPost:
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
			errJSON(w, http.StatusUnsupportedMediaType, "json_required")
			return
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&b); err != nil {
			errJSON(w, http.StatusBadRequest, "invalid_body")
			return
		}
	default:
		errJSON(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if b.Mode != ModeQR && b.Mode != ModePush && b.Mode != ModeWeb2App {
		errJSON(w, http.StatusBadRequest, "invalid_mode")
		return
	}
	if b.Mode == ModeWeb2App && h.cfg.CallbackURL == "" {
		errJSON(w, http.StatusBadRequest, "web2app_not_configured")
		return
	}
	idCode := strings.ToUpper(strings.Join(strings.Fields(b.IDCode), ""))
	if b.Mode == ModePush && !idRe.MatchString(idCode) {
		errJSON(w, http.StatusBadRequest, "invalid_id")
		return
	}
	limited := func() {
		w.Header().Set("Retry-After", "60")
		errJSON(w, http.StatusTooManyRequests, "rate_limited")
	}
	if h.cfg.ClientIP != nil {
		if ip := h.cfg.ClientIP(r); ip != "" && !h.cfg.RateLimit(r.Context(), "start:"+ip) {
			limited()
			return
		}
	}
	if b.Mode == ModePush && !h.cfg.RateLimit(r.Context(), "push:"+idCode) {
		limited()
		return
	}
	lang := "mon"
	if b.Lang == "en" {
		lang = "eng"
	}
	tx, binding, appLink, err := h.begin(r, b.Mode, idCode, lang)
	if err != nil {
		// Иргэн бүртгэлтэй эсэхийг задлахгүй — eID-ийн 4xx/5xx аль нь ч ерөнхий алдаа.
		h.log.Error("eidlogin: session эхлүүлж чадсангүй", "mode", b.Mode, "err", err)
		var ae *eid.APIError
		if errors.As(err, &ae) && ae.Status == http.StatusTooManyRequests {
			limited()
			return
		}
		errJSON(w, http.StatusBadGateway, "eid_unavailable")
		return
	}
	h.setCookie(w, tx.SessionID+"."+binding, int(h.cfg.TTL/time.Second))
	if b.Mode == ModeWeb2App {
		// iOS Universal Link зөвхөн хэрэглэгчийн tap-аас эхэлсэн redirect гинжид аппыг нээнэ — JS биш, 302.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, appLink, http.StatusFound)
		return
	}
	out := map[string]any{"mode": b.Mode, "vc": tx.VC, "expiresIn": int(h.cfg.TTL / time.Second)}
	if q := h.qrLink(tx); q != "" {
		out["qr"] = q
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) begin(r *http.Request, mode Mode, idCode, lang string) (*Tx, string, string, error) {
	ctx := r.Context()
	o := &eid.AuthOptions{CertificateLevel: h.cfg.CertificateLevel}
	tx := &Tx{Mode: mode}
	appLink := ""
	if mode == ModePush {
		s, err := h.cfg.Client.Auth.NotificationByEtsi(ctx, idCode, h.interactions, o)
		if err != nil {
			return nil, "", "", err
		}
		tx.SessionID, tx.VC, tx.ACSP = s.SessionID, s.VC, s.ACSP
	} else {
		if mode == ModeWeb2App {
			o.CallbackURL = WithReturnHint(h.cfg.CallbackURL, r.UserAgent())
		}
		s, err := h.cfg.Client.Auth.DeviceLinkAnonymous(ctx, h.interactions, o)
		if err != nil {
			return nil, "", "", err
		}
		if s.DeviceLinkBase == "" || s.SessionToken == "" || s.SessionSecret == "" || s.ACSP == nil {
			return nil, "", "", errors.New("eID хариунд device link талбар дутуу")
		}
		tx.SessionID, tx.VC, tx.ACSP = s.SessionID, s.VC, s.ACSP
		tx.Link = &Link{Base: s.DeviceLinkBase, Token: s.SessionToken, Secret: s.SessionSecret, ReceivedAt: s.ReceivedAt, Lang: lang}
		if mode == ModeWeb2App {
			appLink, err = eid.BuildDeviceLink(eid.DeviceLinkInput{
				DeviceLinkBase: s.DeviceLinkBase, DeviceLinkType: eid.LinkWeb2App, SessionToken: s.SessionToken,
				SessionSecret: s.SessionSecret, SessionType: eid.SessionAuth, Lang: lang, RPChallenge: s.ACSP.RPChallenge,
				RelyingPartyName: s.ACSP.RelyingPartyName, Interactions: s.ACSP.Interactions,
				InitialCallbackURL: s.ACSP.InitialCallbackURL,
			})
			if err != nil {
				return nil, "", "", err
			}
		}
	}
	if !uuidRe.MatchString(tx.SessionID) {
		return nil, "", "", fmt.Errorf("eID sessionID хэлбэр буруу")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", "", fmt.Errorf("binding: %w", err)
	}
	binding := base64.RawURLEncoding.EncodeToString(raw)
	tx.BindingHash = sha256hex(binding)
	tx.ExpiresAt = time.Now().Add(h.cfg.TTL)
	if err := h.cfg.Store.Set(ctx, tx, h.cfg.TTL); err != nil {
		return nil, "", "", fmt.Errorf("store: %w", err)
	}
	return tx, binding, appLink, nil
}

func isValidation(err error) bool {
	var ve *eid.ValidationError
	var se *eid.SessionFailedError
	return errors.As(err, &ve) || errors.As(err, &se)
}

// finish — COMPLETE/OK-ийг шалгаж нэг удаа OnSuccess дуудна. (nil, nil) = зэрэг хүсэлт аль хэдийн дуусгасан.
func (h *Handler) finish(w http.ResponseWriter, r *http.Request, tx *Tx, res *eid.SessionResult, flow eid.FlowType, verifier string) (*Success, error) {
	v, err := h.cfg.Client.Validator.ValidateAuth(res, tx.ACSP, eid.ValidateAuthOptions{ExpectedFlowType: flow, UserChallengeVerifier: verifier})
	if err != nil {
		return nil, err
	}
	ok, err := h.cfg.Store.Delete(r.Context(), tx.SessionID)
	if err != nil || !ok {
		return nil, err
	}
	id := &Identity{
		SessionID: tx.SessionID,
		ETSI:      v.Subject.SerialNumber, GivenName: v.Subject.GivenName, Surname: v.Subject.Surname, Country: v.Subject.Country,
		DocumentNumber: v.DocumentNumber, CertificateLevel: v.CertificateLevel, Certificate: v.Certificate, FlowType: flow,
	}
	if m := civilRe.FindStringSubmatch(id.ETSI); m != nil {
		id.CivilID = m[1]
	}
	if eid.PersonMatchesCertificate(res.Person, v.Subject) {
		id.Person = res.Person
	}
	s, err := h.cfg.OnSuccess(w, r, id)
	if err != nil {
		return nil, fmt.Errorf("OnSuccess: %w", err)
	}
	if s == nil {
		s = &Success{}
	}
	return s, nil
}

// Status — GET: PENDING (+шинэ QR, vc, expiresIn) | WAIT_CALLBACK | OK | FAILED | EXPIRED.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errJSON(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	expired := func() {
		h.clearCookie(w)
		writeJSON(w, http.StatusOK, map[string]string{"state": "EXPIRED"})
	}
	tx, err := h.loadTx(r)
	if err != nil {
		h.log.Error("eidlogin: store", "err", err)
		errJSON(w, http.StatusInternalServerError, "internal")
		return
	}
	if tx == nil {
		expired()
		return
	}
	res, err := h.cfg.Client.Session.Poll(r.Context(), tx.SessionID, h.cfg.Poll)
	if err != nil {
		var ae *eid.APIError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			h.deleteTx(r.Context(), tx)
			expired()
			return
		}
		h.log.Error("eidlogin: session poll", "err", err)
		errJSON(w, http.StatusBadGateway, "eid_unavailable")
		return
	}
	if res.State != eid.StateComplete {
		left := int(time.Until(tx.ExpiresAt).Seconds() + 0.999)
		out := map[string]any{"state": "PENDING", "vc": tx.VC, "expiresIn": max(0, left)}
		if q := h.qrLink(tx); q != "" {
			out["qr"] = q
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	failed := func(code string) {
		h.deleteTx(r.Context(), tx)
		h.clearCookie(w)
		writeJSON(w, http.StatusOK, map[string]string{"state": "FAILED", "error": code})
	}
	if res.EndResult != eid.EndResultOK {
		failed(orUnknown(res.EndResult))
		return
	}
	// Web2App-аар баталгаажсан session-ийг ЗӨВХӨН callback (userChallengeVerifier) дуусгана.
	if tx.Mode == ModeWeb2App {
		writeJSON(w, http.StatusOK, map[string]string{"state": "WAIT_CALLBACK"})
		return
	}
	flow := eid.FlowQR
	if tx.Mode == ModePush {
		flow = eid.FlowNotification
	}
	s, err := h.finish(w, r, tx, res, flow, "")
	switch {
	case err != nil && isValidation(err):
		h.log.Warn("eidlogin: баталгаажуулалт унасан", "err", err)
		failed("VALIDATION")
	case err != nil:
		h.log.Error("eidlogin: дуусгаж чадсангүй", "err", err)
		errJSON(w, http.StatusInternalServerError, "internal")
	case s == nil:
		expired()
	default:
		h.clearCookie(w)
		out := map[string]any{"state": "OK"}
		if s.Redirect != "" {
			out["redirect"] = s.Redirect
		}
		if s.Data != nil {
			out["data"] = s.Data
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// Callback — GET /auth/eid/callback?sessionId&userChallengeVerifier (Web2App буцалт) → 303.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errJSON(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	fail := func(code string) {
		h.clearCookie(w)
		u := h.failURL
		q := u.Query()
		q.Set("eid_error", code)
		u.RawQuery = q.Encode()
		redirect(w, r, u.String())
	}
	q := r.URL.Query()
	sid, verifier := q.Get("sessionId"), q.Get("userChallengeVerifier")
	tx, err := h.loadTx(r)
	if err != nil {
		h.log.Error("eidlogin: store", "err", err)
		fail("internal")
		return
	}
	// Эхлүүлсэн хөтчийн cookie заавал: өөр хөтчид нээгдсэн callback-ийг (хулгайлсан/илгээсэн URL) хүлээн авахгүй.
	if tx == nil {
		fail("expired")
		return
	}
	if tx.SessionID != sid || tx.Mode != ModeWeb2App || verifier == "" {
		fail("unbound")
		return
	}
	res, err := h.cfg.Client.Session.Poll(r.Context(), tx.SessionID, 10*time.Second)
	if err != nil {
		h.log.Error("eidlogin: session poll", "err", err)
		fail("eid_unavailable")
		return
	}
	if res.State != eid.StateComplete {
		fail("not_complete")
		return
	}
	if res.EndResult != eid.EndResultOK {
		h.deleteTx(r.Context(), tx)
		fail(orUnknown(res.EndResult))
		return
	}
	s, err := h.finish(w, r, tx, res, eid.FlowWeb2App, verifier)
	switch {
	case err != nil && isValidation(err):
		h.log.Warn("eidlogin: баталгаажуулалт унасан", "err", err)
		h.deleteTx(r.Context(), tx)
		fail("VALIDATION")
	case err != nil:
		h.log.Error("eidlogin: дуусгаж чадсангүй", "err", err)
		fail("internal")
	case s == nil:
		fail("expired")
	default:
		h.clearCookie(w)
		to := s.Redirect
		if to == "" {
			to = h.cfg.SuccessRedirect
		}
		redirect(w, r, to)
	}
}

func redirect(w http.ResponseWriter, r *http.Request, to string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (h *Handler) deleteTx(ctx context.Context, tx *Tx) {
	if _, err := h.cfg.Store.Delete(ctx, tx.SessionID); err != nil {
		h.log.Error("eidlogin: store delete", "err", err)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "UNKNOWN"
	}
	return s
}

type browserHint struct {
	re  *regexp.Regexp
	val string
}

// Апп approve-ийн дараа эхэлсэн хөтөч рүү буцах hint (ca-eidmongolia-mn docs/RP_GEREGE_INTEGRATION.md §1.1b).
var (
	iosBrowsers = []browserHint{
		{regexp.MustCompile(`(?i)CriOS`), "googlechromes"},
		{regexp.MustCompile(`(?i)EdgiOS`), "microsoft-edge-https"},
		{regexp.MustCompile(`(?i)FxiOS`), "firefox"},
		{regexp.MustCompile(`(?i)OPT/`), "touch-https"},
		{regexp.MustCompile(`(?i)OPiOS|OPR/`), "opera-https"},
		{regexp.MustCompile(`(?i)DuckDuckGo`), "ddgQuickLink"},
	}
	androidBrowsers = []browserHint{
		{regexp.MustCompile(`(?i)EdgA/`), "com.microsoft.emmx"},
		{regexp.MustCompile(`(?i)Opera Mini`), "com.opera.mini.native"},
		{regexp.MustCompile(`(?i)OPR/`), "com.opera.browser"},
		{regexp.MustCompile(`(?i)SamsungBrowser/`), "com.sec.android.app.sbrowser"},
		{regexp.MustCompile(`(?i)YaBrowser/`), "com.yandex.browser"},
		{regexp.MustCompile(`(?i)DuckDuckGo/`), "com.duckduckgo.mobile.android"},
		{regexp.MustCompile(`(?i)Vivaldi/`), "com.vivaldi.browser"},
		{regexp.MustCompile(`(?i)Firefox/`), "org.mozilla.firefox"},
		{regexp.MustCompile(`(?i)Chrome/`), "com.android.chrome"},
	}
	iosRe     = regexp.MustCompile(`(?i)iPhone|iPad|iPod`)
	androidRe = regexp.MustCompile(`(?i)Android`)
)

// WithReturnHint — callbackURL-д буцах хөтчийн hint (retScheme iOS / retPkg Android) нэмнэ; танихгүй бол хэвээр.
func WithReturnHint(callbackURL, userAgent string) string {
	pick := func(t []browserHint) string {
		for _, b := range t {
			if b.re.MatchString(userAgent) {
				return b.val
			}
		}
		return ""
	}
	key, val := "", ""
	switch {
	case iosRe.MatchString(userAgent):
		key, val = "retScheme", pick(iosBrowsers)
	case androidRe.MatchString(userAgent):
		key, val = "retPkg", pick(androidBrowsers)
	}
	if val == "" {
		return callbackURL
	}
	u, err := url.Parse(callbackURL)
	if err != nil {
		return callbackURL
	}
	q := u.Query()
	q.Set(key, val)
	u.RawQuery = q.Encode()
	return u.String()
}
