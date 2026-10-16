package eid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

// Гарын үсэгтэй файлыг имэйлээр дамжуулах — POST /share (CA docs/SHARE_EMAIL.md, main 0329ef95). RP гарын үсэг зурсан
// файлаа дараагийн гарын үсэг зурагч / хүлээн авагч руу хавсралтаар илгээнэ. CA файлыг хадгалахгүй: eID-ийн хүчинтэй
// гарын үсэгтэй эсэхийг шалгаад email-service руу дамжуулж хаяна. SIGN эрх. CA-ийн туг (EID_SHARE_ENABLED)
// унтраалттай үед 503 SHARE_DISABLED — ShareInfo().Enabled-ээр урьдчилан шалга.

// DefaultShareTimeout — Share-ийн хүсэлтийн хугацаа: CA бүх хүлээн авагчид 120 с-д илгээнэ, nginx 150 с. ctx-ийн
// deadline богино бол тэр нь ялна.
const DefaultShareTimeout = 150 * time.Second

// shareFormFields — POST /share-ийн multipart талбарууд (CA handlers_share.go parseShareRequest; үл мэдэгдэх талбар
// 400). Гэрээний тест discovery-ийн endpoints.share-тэй тулгана.
var shareFormFields = []string{"file", "filename", "to", "subject", "message", "lang"}

// ShareRequest — Share-ийн оролт. Хязгаар: discovery-ийн share блок (ShareInfo).
type ShareRequest struct {
	// File — гарын үсэгтэй файл (одоогоор зөвхөн PDF), ≤ 3 080 192 байт.
	File []byte
	// Filename — хавсралтын нэр (≤ 120 тэмдэгт); өргөтгөл нь форматтай таарах ёстой (.pdf), эс бөгөөс 415. "" =
	// "document.pdf".
	Filename string
	// To — хүлээн авагч, 1–5 (хүн бүрт тусдаа имэйл). Давхардвал 400 RECIPIENT_DUPLICATE.
	To []string
	// Subject — имэйлийн гарчиг (≤ 150); CA үргэлж «‹RP нэр›: …» угтвар тавина.
	Subject string
	// Message — илгээгчийн тэмдэглэл (≤ 1000).
	Message string
	// Lang — имэйлийн хэл: "mn" (анхдагч, "") | "en".
	Lang string
}

// ShareResult — 200 хариу.
type ShareResult struct {
	// Sent — илгээсэн имэйлийн тоо.
	Sent int `json:"sent"`
	// SHA256 — файлын SHA-256 (hex).
	SHA256 string `json:"sha256"`
	// Signatures — хүчинтэй eID гарын үсгийн тоо.
	Signatures int `json:"signatures"`
	// DocID — CA-д (/pdf/signatures) бүртгэлтэй бол баримтын ID (имэйлд verify холбоос орно); үгүй бол "".
	DocID string          `json:"docID,omitempty"`
	Raw   json.RawMessage `json:"-"`
}

// Share-ийн алдааны кодууд — ShareError.Code (CodeRequestInvalid, CodeRateLimited-ийг мөн буцаана).
const (
	CodeFileEmpty            = "FILE_EMPTY"
	CodeRecipientRequired    = "RECIPIENT_REQUIRED"
	CodeTooManyRecipients    = "TOO_MANY_RECIPIENTS"
	CodeRecipientInvalid     = "RECIPIENT_INVALID"
	CodeRecipientDuplicate   = "RECIPIENT_DUPLICATE"
	CodeFileTooLarge         = "FILE_TOO_LARGE"          // 413
	CodeFileTypeNotSupported = "FILE_TYPE_NOT_SUPPORTED" // 415
	CodeFileNotSigned        = "FILE_NOT_SIGNED"         // 422 + Reason
	CodeMailFailed           = "MAIL_FAILED"             // 502 + Sent/Failed/Recipients
	CodeShareDisabled        = "SHARE_DISABLED"          // 503
	CodeMailUnavailable      = "MAIL_UNAVAILABLE"        // 503
	CodeValidatorUnavailable = "VALIDATOR_UNAVAILABLE"   // 503 (+ Retry-After)
	CodeValidatorBusy        = "VALIDATOR_BUSY"          // 503 + Retry-After
)

// ShareErrorCodes — Share-ийн бүх алдааны код.
var ShareErrorCodes = []string{
	CodeRequestInvalid, CodeFileEmpty, CodeRecipientRequired, CodeTooManyRecipients, CodeRecipientInvalid,
	CodeRecipientDuplicate, CodeFileTooLarge, CodeFileTypeNotSupported, CodeFileNotSigned, CodeRateLimited,
	CodeMailFailed, CodeShareDisabled, CodeMailUnavailable, CodeValidatorUnavailable, CodeValidatorBusy,
}

// 422 FILE_NOT_SIGNED-ийн шалтгаан — ShareError.Reason.
const (
	ShareReasonNoSignature = "no_signature" // файлд цахим гарын үсэг алга
	ShareReasonInvalid     = "invalid"      // эвдэрсэн / агуулга өөрчлөгдсөн / цуцлагдсан / хэт олон
	ShareReasonUntrusted   = "untrusted"    // eID-ийн итгэмжлэгдсэн гинжид холбогдохгүй, эсвэл eID-ийн бус харагдах гарын үсэг
)

// Share-ийн хүлээн авагчийн төлөв — ShareError.Recipients.
const (
	ShareRecipientSent   = "sent"
	ShareRecipientFailed = "failed"
)

// ShareError — Share-ийн CA алдаа (401/403-аас бусад 4xx/5xx; 401 → *AuthenticationError, 403 → *ForbiddenError).
// errors.As(err, &*ShareError)-аар Reason/Sent/Failed/Recipients, errors.As(err, &*APIError)-аар
// Status/Code/RetryAfter (Unwrap). JSON биш хариу (proxy) бол Code "".
type ShareError struct {
	APIError
	// Reason — 422 FILE_NOT_SIGNED: ShareReasonNoSignature | ShareReasonInvalid | ShareReasonUntrusted.
	Reason string
	// Sent, Failed — 502 MAIL_FAILED: амжилттай / амжилтгүй тоо.
	Sent, Failed int
	// Recipients — 502 MAIL_FAILED: To-гийн дарааллаар ShareRecipientSent | ShareRecipientFailed. Зөвхөн failed-ийг
	// дахин илгээ (амжилттайг дахин бүү илгээ).
	Recipients []string
}

func (e *ShareError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("eid: share %d", e.Status)
	}
	if e.Reason != "" {
		return fmt.Sprintf("eid: share %d %s (%s)", e.Status, e.Code, e.Reason)
	}
	return fmt.Sprintf("eid: share %d %s", e.Status, e.Code)
}

// Unwrap — errors.As(err, &*APIError) ба errors.Is(err, ErrRequestInvalid).
func (e *ShareError) Unwrap() error { return &e.APIError }

func newShareError(ae *APIError) *ShareError {
	se := &ShareError{APIError: *ae}
	var v struct {
		Reason     string   `json:"reason"`
		Sent       int      `json:"sent"`
		Failed     int      `json:"failed"`
		Recipients []string `json:"recipients"`
	}
	if json.Unmarshal([]byte(ae.Body), &v) == nil {
		se.Reason, se.Sent, se.Failed, se.Recipients = v.Reason, v.Sent, v.Failed, v.Recipients
	}
	return se
}

// Share — POST /share (SIGN эрх): гарын үсэгтэй файлыг (PDF, eID-ийн хүчинтэй гарын үсэгтэй) 1–5 хүлээн авагч руу
// имэйлээр, хавсралтаар илгээнэ; CA файлыг хадгалахгүй. Алдаа: *ShareError (Code, 422-д Reason, 502-д
// Sent/Failed/Recipients), 401 *AuthenticationError, 403 *ForbiddenError, сүлжээ *NetworkError.
func (c *Client) Share(ctx context.Context, r ShareRequest) (*ShareResult, error) {
	body, ctype, err := shareBody(r)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.h.doJSON(ctx, http.MethodPost, routeShare.expand(), bytes.NewReader(body), ctype, DefaultShareTimeout, &raw); err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			return nil, newShareError(ae)
		}
		return nil, err
	}
	var out ShareResult
	if err := decodeJSON(raw, routeShare.path, &out); err != nil {
		return nil, err
	}
	out.Raw = raw
	return &out, nil
}

// shareBody — multipart/form-data. Файлын хэсгийн нэр зөвхөн ASCII (Content-Disposition); Unicode нэрийг filename
// талбараар дамжуулна (CA тэр талбарыг давуу үзнэ).
func shareBody(r ShareRequest) ([]byte, string, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	field := func(k, v string) error {
		if v == "" {
			return nil
		}
		return w.WriteField(k, v)
	}
	for _, a := range r.To {
		if err := w.WriteField("to", a); err != nil {
			return nil, "", fmt.Errorf("eid: share: %w", err)
		}
	}
	for _, kv := range [][2]string{{"subject", r.Subject}, {"message", r.Message}, {"lang", r.Lang}, {"filename", r.Filename}} {
		if err := field(kv[0], kv[1]); err != nil {
			return nil, "", fmt.Errorf("eid: share: %w", err)
		}
	}
	partName := "document.pdf"
	if r.Filename != "" && isPrintableASCII(r.Filename) {
		partName = r.Filename
	}
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename="`+quoteEscaper.Replace(partName)+`"`)
	h.Set("Content-Type", "application/pdf")
	p, err := w.CreatePart(h)
	if err != nil {
		return nil, "", fmt.Errorf("eid: share: %w", err)
	}
	if _, err := p.Write(r.File); err != nil {
		return nil, "", fmt.Errorf("eid: share: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("eid: share: %w", err)
	}
	return b.Bytes(), w.FormDataContentType(), nil
}

var quoteEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ShareInfo — discovery (/.well-known/eid)-ийн share блок.
type ShareInfo struct {
	// Enabled — CA-ийн туг. false бол Share → 503 SHARE_DISABLED.
	Enabled  bool          `json:"enabled"`
	Endpoint string        `json:"endpoint"`
	Formats  []ShareFormat `json:"formats"`
	// Languages — имэйлийн хэл (mn, en).
	Languages        []string `json:"languages"`
	MaxFileBytes     int      `json:"maxFileBytes"`
	MaxFilenameChars int      `json:"maxFilenameChars"`
	MaxMessageChars  int      `json:"maxMessageChars"`
	MaxRecipients    int      `json:"maxRecipients"`
	MaxSubjectChars  int      `json:"maxSubjectChars"`
	// Permission — шаардлагатай RP эрх (SIGN).
	Permission             string          `json:"permission"`
	Quota                  ShareQuota      `json:"quota"`
	RequiresValidSignature bool            `json:"requiresValidSignature"`
	Raw                    json.RawMessage `json:"-"`
}

// ShareFormat — дэмжигдэх формат (одоогоор pdf).
type ShareFormat struct {
	Name      string `json:"name"`
	Extension string `json:"extension"`
	MIME      string `json:"mime"`
}

// ShareQuota — RP тутам цаг/өдөр (хүсэлт), хүлээн авагч тутам өдөр (имэйл, RP тус бүрд).
type ShareQuota struct {
	PerRPHour       int `json:"perRPHour"`
	PerRPDay        int `json:"perRPDay"`
	PerRecipientDay int `json:"perRecipientDay"`
}

const discoveryPath = "/.well-known/eid"

// ShareInfo — discovery-ийн share блок. Блок байхгүй (хуучин CA) бол Enabled false.
func (c *Client) ShareInfo(ctx context.Context) (*ShareInfo, error) {
	var d struct {
		Share json.RawMessage `json:"share"`
	}
	if err := c.h.getJSON(ctx, discoveryPath, 0, &d); err != nil {
		return nil, err
	}
	var out ShareInfo
	if len(d.Share) > 0 && string(d.Share) != "null" {
		if err := decodeJSON(d.Share, discoveryPath, &out); err != nil {
			return nil, err
		}
		out.Raw = d.Share
	}
	return &out, nil
}
