package eid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL — RP-API-ийн албан ёсны хост (2026-09-28-наас бүх RP, /v3-гүй). mTLS-тэй RP ч мөн энэ хост.
const DefaultBaseURL = "https://rp.eidmongolia.mn"

const (
	defaultTimeout = 15 * time.Second
	// DefaultPDFTimeout — PDF.RegisterSignature-ийн анхдагч хугацаа (CA CMS + TSA + LTV-г шалгадаг), CA-ийн nginx
	// proxy_read_timeout-оос бага.
	DefaultPDFTimeout = 80 * time.Second
	maxErrorBody      = 64 << 10
	// maxJSONBody — JSON хариуны дээд хэмжээ; хэтэрвэл *ResponseTooLargeError (таслахгүй).
	maxJSONBody = 4 << 20
)

// Хуучин (0.2.x TS) хэлбэр: ca. хост руу /v3 залгадаг байсан — чимээгүй 404-ийн оронд тодорхой алдаа.
var legacyHosts = map[string]bool{"ca.eidmongolia.mn": true, "e-id.mn": true, "www.e-id.mn": true}

// Config — Client-ийн тохиргоо.
type Config struct {
	// BaseURL — RP-API-ийн БҮТЭН суурь URL; SDK зам залгахаас өөр юу ч нэмэхгүй. "" = DefaultBaseURL.
	BaseURL string
	// Credentials — RP таних мэдээлэл + API secret (заавал).
	Credentials Credentials
	// DefaultCertificateLevel — auth/sign бүрийн анхдагч certLevel. "" = QUALIFIED.
	DefaultCertificateLevel CertificateLevel
	// Timeout — нэг HTTP дуудлагын анхдагч хугацаа. 0 = 15s. Long-poll ба PDF өөрийн уртыг хэрэглэнэ.
	Timeout time.Duration
	// PDFTimeout — PDF.RegisterSignature-ийн дуудлагын хугацаа. 0 = DefaultPDFTimeout (80s).
	PDFTimeout time.Duration
	// HTTPClient — mTLS client cert (tls.Config.Certificates) эсвэл proxy тохируулахад. nil = шинэ http.Client.
	HTTPClient *http.Client
	// Trust — validator-ийн итгэлийн тохиргоо. Production-д TrustAnchorsPEM ЗААВАЛ.
	Trust TrustConfig
	// SignSessionTTL — sign / certificate-choice session-ий ExpiresAt-ийг тооцоолох хугацаа (SessionExpiry). 0 =
	// DefaultSignSessionTTL (600s, CA-ийн анхдагч). CA-ийн админ тохиргоог өөрчилсөн бол үүнийг тааруул.
	SignSessionTTL time.Duration
	// Language — хүнд харуулах текстийн хэл (RoleLabel г.м.): дуудлага бүрд Accept-Language болж илгээгдэнэ
	// ("mn" | "en"). "" = илгээхгүй (сервер mn).
	Language string
}

// Client — SDK-ийн гол үүд:
//
//	Auth         — нэвтрэлт эхлүүлэх (push / device link)
//	Sign         — гарын үсэг эхлүүлэх (digest; push / device link) ба гэрчилгээ сонгуулах (certificate-choice)
//	PDF          — клиент талын PAdES-ийн CMS бүртгэл (RegisterSignature); угсралт = pades
//	Organization — иргэний төлөөлөх байгууллагууд
//	Person       — иргэний PKI самбар (PKI_READ эрх): гэрчилгээ, төхөөрөмж, үйл ажиллагаа, тоо, хүүхдүүд
//	Token        — USB токены гэрчилгээ олголт (TOKEN_ISSUE) ба токеноор нэвтрэлт (AUTH)
//	Session      — үр дүн long-poll
//	Validator    — хариуг крипто-баталгаажуулах (гинж + гарын үсэг)
//	c.Share / c.ShareInfo (method) — гарын үсэгтэй файлыг имэйлээр (SIGN); ShareInfo — discovery-ийн share блок
//	             (enabled, хязгаар, квот)
//
// Client нь goroutine-safe.
type Client struct {
	Auth         *AuthService
	Sign         *SignService
	PDF          *PDFService
	Organization *OrganizationService
	Person       *PersonService
	Token        *TokenService
	Session      *SessionService
	Validator    *Validator

	rpName string
	h      *httpDoer
}

// RPName — Credentials.RPName (иргэний утсанд харагдах RP нэр).
func (c *Client) RPName() string { return c.rpName }

// NewClient — тохиргоог шалгаж Client үүсгэнэ.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Credentials.APISecret == "" {
		return nil, errors.New("eid: Credentials.APISecret шаардлагатай")
	}
	base, err := ResolveBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	v, err := NewValidator(cfg.Trust)
	if err != nil {
		return nil, err
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{}
	}
	t := cfg.Timeout
	if t <= 0 {
		t = defaultTimeout
	}
	level := cfg.DefaultCertificateLevel
	if level == "" {
		level = LevelQualified
	}
	pt := cfg.PDFTimeout
	if pt <= 0 {
		pt = DefaultPDFTimeout
	}
	h := &httpDoer{base: base, secret: cfg.Credentials.APISecret, timeout: t, hc: hc, lang: strings.TrimSpace(cfg.Language)}
	return &Client{
		Auth:         &AuthService{h: h, creds: cfg.Credentials, level: level},
		Sign:         &SignService{h: h, creds: cfg.Credentials, level: level, ttl: cfg.SignSessionTTL},
		PDF:          &PDFService{h: h, timeout: pt},
		Organization: &OrganizationService{h: h},
		Person:       &PersonService{h: h},
		Token:        &TokenService{h: h, creds: cfg.Credentials, v: v},
		Session:      &SessionService{h: h},
		Validator:    v,
		rpName:       cfg.Credentials.RPName,
		h:            h,
	}, nil
}

// ResolveBaseURL — baseURL-ийг шалгаж, төгсгөлийн "/"-ийг хасна ("" = DefaultBaseURL). Хуучин ca. хост (/v3-тай
// байсан) бол тодорхой алдаа.
func ResolveBaseURL(baseURL string) (string, error) {
	raw := strings.TrimSpace(baseURL)
	if raw == "" {
		raw = DefaultBaseURL
	}
	raw = strings.TrimRight(raw, "/")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("eid: BaseURL буруу URL: %s", raw)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return "", fmt.Errorf("eid: BaseURL https байх ёстой (http зөвхөн localhost/loopback): %s", raw)
	}
	if legacyHosts[u.Hostname()] && u.Path == "" {
		return "", fmt.Errorf("eid: RP-API %s-аас %s руу шилжсэн (/v3-гүй) — BaseURL-ийг %s болгоно уу (эсвэл хоосон орхи)",
			u.Hostname(), DefaultBaseURL, DefaultBaseURL)
	}
	return raw, nil
}

// isLoopback — localhost эсвэл loopback IP (127.0.0.0/8, ::1): API secret сүлжээгээр нээлттэй явахгүй.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// httpDoer — RP-API HTTP давхарга: Bearer secret, timeout, HTTP статусыг төрөлжсөн алдаа руу буулгана.
type httpDoer struct {
	base    string
	secret  string
	timeout time.Duration
	hc      *http.Client
	lang    string // Accept-Language; "" = илгээхгүй
}

func (h *httpDoer) postJSON(ctx context.Context, path string, body, out any) error {
	return h.postJSONTimeout(ctx, path, body, 0, out)
}

func (h *httpDoer) postJSONTimeout(ctx context.Context, path string, body any, timeout time.Duration, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("eid: request encode: %w", err)
	}
	return h.doJSON(ctx, http.MethodPost, path, bytes.NewReader(b), "application/json", timeout, out)
}

func (h *httpDoer) getJSON(ctx context.Context, path string, timeout time.Duration, out any) error {
	return h.doJSON(ctx, http.MethodGet, path, nil, "", timeout, out)
}

func (h *httpDoer) doJSON(ctx context.Context, method, path string, body io.Reader, ctype string, timeout time.Duration, out any) error {
	_, err := h.doJSONStatus(ctx, method, path, body, ctype, timeout, out)
	return err
}

// postJSONStatus — postJSONTimeout + амжилттай хариуны HTTP статус (201 / 200-г ялгах: POST /pdf/signatures).
func (h *httpDoer) postJSONStatus(ctx context.Context, path string, body any, timeout time.Duration, out any) (int, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("eid: request encode: %w", err)
	}
	return h.doJSONStatus(ctx, http.MethodPost, path, bytes.NewReader(b), "application/json", timeout, out)
}

func (h *httpDoer) doJSONStatus(ctx context.Context, method, path string, body io.Reader, ctype string, timeout time.Duration, out any) (int, error) {
	ctx, cancel := h.withTimeout(ctx, timeout)
	defer cancel()
	res, err := h.send(ctx, method, path, body, ctype)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	raw, err := readLimited(res, maxJSONBody, method, path)
	if err != nil {
		return 0, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return res.StatusCode, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return 0, fmt.Errorf("eid: %s %s: хариу задарсангүй: %w", method, maskPath(path), err)
	}
	return res.StatusCode, nil
}

// decodeJSON — getJSON-оор авсан түүхий хариуг задлах (алдааны текстэд таних тэмдэггүй зам).
func decodeJSON(raw []byte, path string, out any) error {
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("eid: %s: хариу задарсангүй: %w", maskPath(path), err)
	}
	return nil
}

// readLimited — хариуны биеийг limit хүртэл уншина; Content-Length эсвэл бодит урт limit-ээс хэтэрвэл
// *ResponseTooLargeError (таслагдсан биеийг буцаахгүй).
func readLimited(res *http.Response, limit int64, method, path string) ([]byte, error) {
	if res.ContentLength > limit {
		return nil, &ResponseTooLargeError{Op: method + " " + maskPath(path), Limit: limit}
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, netErr(method, path, err)
	}
	if int64(len(b)) > limit {
		return nil, &ResponseTooLargeError{Op: method + " " + maskPath(path), Limit: limit}
	}
	return b, nil
}

func (h *httpDoer) withTimeout(ctx context.Context, t time.Duration) (context.Context, context.CancelFunc) {
	if t <= 0 {
		t = h.timeout
	}
	return context.WithTimeout(ctx, t)
}

// send — амжилттай (< 300) хариуг буцаана; бусад статусыг төрөлжсөн алдаа болгоно (бие нь хаагдана).
func (h *httpDoer) send(ctx context.Context, method, path string, body io.Reader, ctype string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, h.base+path, body)
	if err != nil {
		return nil, fmt.Errorf("eid: request %s %s: %w", method, maskPath(path), unwrapURL(err))
	}
	req.Header.Set("Authorization", "Bearer "+h.secret)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if h.lang != "" {
		req.Header.Set("Accept-Language", h.lang)
	}
	res, err := h.hc.Do(req)
	if err != nil {
		return nil, netErr(method, path, err)
	}
	if res.StatusCode < 300 {
		return res, nil
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, maxErrorBody))
	msg, code := errorBody(raw)
	retry := parseRetryAfter(res.Header.Get("Retry-After"), time.Now())
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return nil, &AuthenticationError{Code: code, Message: msg, Body: string(raw), Header: res.Header}
	case http.StatusForbidden:
		return nil, &ForbiddenError{Code: code, Message: msg, RetryAfter: retry, Header: res.Header}
	}
	return nil, &APIError{Status: res.StatusCode, Body: string(raw), Code: code, RetryAfter: retry, Header: res.Header}
}

// errorBody — серверийн алдааны JSON {"error","code"}; JSON биш (proxy) бол хоосон.
func errorBody(raw []byte) (msg, code string) {
	var v struct {
		Error any `json:"error"`
		Code  any `json:"code"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return "", ""
	}
	msg, _ = v.Error.(string)
	code, _ = v.Code.(string)
	return msg, code
}

// netErr — Op-д таних тэмдэггүй зам (maskPath), Err-д *url.Error-ийн оронд доторх шалтгаан (бүтэн URL-д PNOMN
// байдаг) — алдааны текстэд иргэний дугаар орохгүй.
func netErr(method, path string, err error) error {
	var ne net.Error
	timeout := errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
	return &NetworkError{Op: method + " " + maskPath(path), Timeout: timeout, Err: unwrapURL(err)}
}

// unwrapURL — *url.Error (Op + бүтэн URL + шалтгаан) → шалтгаан.
func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

// vcValue — vc нь мөр эсвэл {"type","value"} объект байж болно.
type vcValue string

func (v *vcValue) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*v = vcValue(s)
		return nil
	}
	var o struct {
		Value *string `json:"value"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	if o.Value != nil {
		*v = vcValue(*o.Value)
	}
	return nil
}
