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
	pdfTimeout     = 60 * time.Second
	maxErrorBody   = 64 << 10
	maxJSONBody    = 4 << 20
	maxPDFBody     = 64 << 20
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
	// HTTPClient — mTLS client cert (tls.Config.Certificates) эсвэл proxy тохируулахад. nil = шинэ http.Client.
	HTTPClient *http.Client
	// Trust — validator-ийн итгэлийн тохиргоо. Production-д TrustAnchorsPEM ЗААВАЛ.
	Trust TrustConfig
}

// Client — SDK-ийн гол үүд:
//
//	Auth         — нэвтрэлт эхлүүлэх (push / device link)
//	Sign         — гарын үсэг эхлүүлэх (digest)
//	PDF          — PAdES гарын үсэг (CA угсарна; OnBehalfOf)
//	Organization — иргэний төлөөлөх байгууллагууд
//	Session      — үр дүн long-poll
//	Validator    — хариуг крипто-баталгаажуулах (гинж + гарын үсэг)
//
// Client нь goroutine-safe.
type Client struct {
	Auth         *AuthService
	Sign         *SignService
	PDF          *PDFService
	Organization *OrganizationService
	Session      *SessionService
	Validator    *Validator
}

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
	h := &httpDoer{base: base, secret: cfg.Credentials.APISecret, timeout: t, hc: hc}
	return &Client{
		Auth:         &AuthService{h: h, creds: cfg.Credentials, level: level},
		Sign:         &SignService{h: h, creds: cfg.Credentials, level: level},
		PDF:          &PDFService{h: h, creds: cfg.Credentials, level: level},
		Organization: &OrganizationService{h: h},
		Session:      &SessionService{h: h},
		Validator:    v,
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
	if legacyHosts[u.Hostname()] && u.Path == "" {
		return "", fmt.Errorf("eid: RP-API %s-аас %s руу шилжсэн (/v3-гүй) — BaseURL-ийг %s болгоно уу (эсвэл хоосон орхи)",
			u.Hostname(), DefaultBaseURL, DefaultBaseURL)
	}
	return raw, nil
}

// httpDoer — RP-API HTTP давхарга: Bearer secret, timeout, HTTP статусыг төрөлжсөн алдаа руу буулгана.
type httpDoer struct {
	base    string
	secret  string
	timeout time.Duration
	hc      *http.Client
}

func (h *httpDoer) postJSON(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("eid: request encode: %w", err)
	}
	return h.doJSON(ctx, http.MethodPost, path, bytes.NewReader(b), "application/json", 0, out)
}

func (h *httpDoer) getJSON(ctx context.Context, path string, timeout time.Duration, out any) error {
	return h.doJSON(ctx, http.MethodGet, path, nil, "", timeout, out)
}

func (h *httpDoer) doJSON(ctx context.Context, method, path string, body io.Reader, ctype string, timeout time.Duration, out any) error {
	ctx, cancel := h.withTimeout(ctx, timeout)
	defer cancel()
	res, err := h.send(ctx, method, path, body, ctype)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxJSONBody))
	if err != nil {
		return netErr(method+" "+path, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("eid: %s %s: хариу задарсангүй: %w", method, path, err)
	}
	return nil
}

func (h *httpDoer) getBytes(ctx context.Context, path string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := h.withTimeout(ctx, timeout)
	defer cancel()
	res, err := h.send(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxPDFBody))
	if err != nil {
		return nil, netErr("GET "+path, err)
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
		return nil, fmt.Errorf("eid: request %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+h.secret)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	res, err := h.hc.Do(req)
	if err != nil {
		return nil, netErr(method+" "+path, err)
	}
	if res.StatusCode < 300 {
		return res, nil
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, maxErrorBody))
	msg, code := errorBody(raw)
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return nil, &AuthenticationError{}
	case http.StatusForbidden:
		return nil, &ForbiddenError{Code: code, Message: msg}
	}
	return nil, &APIError{Status: res.StatusCode, Body: string(raw), Code: code}
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

func netErr(op string, err error) error {
	var ne net.Error
	timeout := errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
	return &NetworkError{Op: op, Timeout: timeout, Err: err}
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
