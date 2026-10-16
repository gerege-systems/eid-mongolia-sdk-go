package eid

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPOptions — NewOCSPChecker-ийн тохиргоо (бүгд заавал биш).
type OCSPOptions struct {
	// HTTPClient — анхдагч: timeout 2 с, redirect дагахгүй (responder нь CA-ийн гэрчилгээнд бичсэн URL; plain HTTP
	// дээрх 302 нь өөр хэн нэгнийх).
	HTTPClient *http.Client
	// Now — цаг (тест). nil бол time.Now.
	Now func() time.Time
	// CacheTTL — "good" хариуг кэшлэх дээд хугацаа; бодит хугацаа = min(CacheTTL, хариуны NextUpdate − одоо). 0 бол 5 мин;
	// сөрөг бол кэшлэхгүй.
	CacheTTL time.Duration
	// Observe — шалгалт бүрийн дараа (кэшээс ч) дуудагдана: метрик / аудит. PII-гүй (serial, нэр орохгүй). Синхрон
	// дуудагдана — удаан ажил бүү хий; panic хийхгүй байх ёстой.
	Observe func(OCSPObservation)
}

// OCSPObservation — NewOCSPChecker-ийн нэг шалгалтын үр дүн (OCSPOptions.Observe). Иргэний таних мэдээлэлгүй.
type OCSPObservation struct {
	// Status — буцаасан төлөв: RevocationGood / RevocationRevoked / RevocationUnknown (хариугүй).
	Status RevocationStatus
	// Responder — хариулсан (эсвэл хамгийн сүүлд оролдсон) responder URL; кэш / AIA алга бол "".
	Responder string
	// Duration — сүлжээгээр асуусан нийт хугацаа (кэшээс бол 0).
	Duration time.Duration
	// Cached — кэшээс хариулсан.
	Cached bool
	// Err — хариугүй бол шалтгаан (*OCSPError, errors.Is(Err, ErrOCSPNoAnswer)); бусад үед nil.
	Err error
}

// ErrOCSPNoAnswer — NewOCSPChecker хүчинтэй хариу авсангүй (RevocationUnknown-тэй хамт *OCSPError-оор буцна).
// Validator.CheckRevocationWith үүнийг "unknown" гэж үзэж горимоор шийднэ (soft → unchecked; hard → *ValidationError,
// errors.Is(err, ErrOCSPNoAnswer) үнэн).
var ErrOCSPNoAnswer = errors.New("eid: OCSP хариу алга")

// OCSPErrorKind — OCSP хариу авч чадаагүй шалтгааны ангилал.
type OCSPErrorKind string

const (
	// OCSPNoResponder — гэрчилгээний AIA-д дэмжигдэх (http/https) OCSP URL алга.
	OCSPNoResponder OCSPErrorKind = "no_responder"
	// OCSPNoIssuer — олгогчийн гэрчилгээ олдоогүй (leaf эсвэл issuer nil).
	OCSPNoIssuer OCSPErrorKind = "no_issuer"
	// OCSPTimeout — хугацаа хэтэрсэн (2 с / нийт 3 с) эсвэл ctx цуцлагдсан.
	OCSPTimeout OCSPErrorKind = "timeout"
	// OCSPNetwork — холболтын бусад алдаа (DNS, TCP, TLS).
	OCSPNetwork OCSPErrorKind = "network"
	// OCSPHTTPStatus — HTTP статус 200 биш (OCSPError.HTTPStatus), эсвэл хариу хэт том.
	OCSPHTTPStatus OCSPErrorKind = "http_status"
	// OCSPResponderStatus — OCSP responseStatus амжилтгүй (malformedRequest, tryLater, unauthorized г.м.).
	OCSPResponderStatus OCSPErrorKind = "responder_status"
	// OCSPParse — хариу DER/ASN.1 задрахгүй.
	OCSPParse OCSPErrorKind = "parse"
	// OCSPSignature — хариуны (эсвэл responder гэрчилгээний) гарын үсэг олгогчтой таарахгүй, responder-ийн EKU /
	// хугацаа буруу.
	OCSPSignature OCSPErrorKind = "signature"
	// OCSPInvalid — гарын үсэг зөв ч агуулга хүлээн авахгүй: өөр serial, thisUpdate хүрээнээс гадуур, nextUpdate өнгөрсөн.
	OCSPInvalid OCSPErrorKind = "invalid"
)

// OCSPError — NewOCSPChecker хариу авч чадаагүй шалтгаан. errors.Is(err, ErrOCSPNoAnswer) үнэн. Мессеж PII-гүй.
type OCSPError struct {
	Kind OCSPErrorKind
	// Responder — оролдсон URL ("" — AIA алга / issuer алга).
	Responder string
	// HTTPStatus — Kind == OCSPHTTPStatus үед.
	HTTPStatus int
	Err        error
}

func (e *OCSPError) Error() string {
	msg := "eid: OCSP " + string(e.Kind)
	if e.Responder != "" {
		msg += " (" + e.Responder + ")"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *OCSPError) Unwrap() []error {
	if e.Err == nil {
		return []error{ErrOCSPNoAnswer}
	}
	return []error{ErrOCSPNoAnswer, e.Err}
}

const (
	ocspTimeout      = 2 * time.Second
	ocspTotalTimeout = 3 * time.Second
	ocspCacheTTL     = 5 * time.Minute
	ocspCacheMax     = 1024
	ocspMaxBytes     = 16 << 10
	ocspClockSkew    = 5 * time.Minute
	// ocspMaxAge — хамгийн хуучин thisUpdate. CA хариу бүрийг шинээр зурдаг (thisUpdate = now, nextUpdate = +24 ц);
	// энэ хязгаар нь цуцлалтаас өмнө авсан "good"-ийг plain HTTP-ээр давтан тоглуулахаас хамгаална.
	ocspMaxAge = 48 * time.Hour
)

type ocspEntry struct {
	status  RevocationStatus
	expires time.Time
}

// NewOCSPChecker — гэрчилгээний AIA-д бичигдсэн OCSP responder-оос асууж төлвийг буцаах RevocationChecker (eID
// порталын EID_OCSP-тэй ижил дүрэм):
//
//   - good → RevocationGood (min(CacheTTL=5 мин, NextUpdate) кэшлэнэ);
//   - revoked, мөн unknown (олгогч энэ serial-ийг олгоогүй — өөр хэн нэгний хийсэн гэрчилгээ) → RevocationRevoked;
//   - хариугүй (AIA алга, issuer олдоогүй, timeout, 5xx, гарын үсэг/serial/хугацаа таараагүй хариу) → RevocationUnknown
//     ба *OCSPError (errors.Is(err, ErrOCSPNoAnswer)). Validator-ийн RevocationMode шийднэ: soft-fail — зөвшөөрнө
//     (unchecked), hard-fail — татгалзана (*ValidationError, шалтгаан нь Unwrap-аар).
//
// Хариуг олгогч эсвэл олгогчийн гаргасан id-kp-OCSPSigning EKU-тэй (одоо хүчинтэй, хариунд шигтгэсэн — RFC 6960
// §4.2.2.2 delegated) responder зурсан, энэ serial-ийн тухай, thisUpdate нь [now−48ц, now+5мин], nextUpdate
// өнгөрөөгүй байх ёстой.
func NewOCSPChecker(opts OCSPOptions) RevocationChecker {
	o := &ocspChecker{http: opts.HTTPClient, now: opts.Now, ttl: opts.CacheTTL, observe: opts.Observe, cache: map[string]ocspEntry{}}
	if o.http == nil {
		o.http = &http.Client{Timeout: ocspTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.ttl == 0 {
		o.ttl = ocspCacheTTL
	}
	return o.check
}

type ocspChecker struct {
	http    *http.Client
	now     func() time.Time
	ttl     time.Duration
	observe func(OCSPObservation)

	mu    sync.Mutex
	cache map[string]ocspEntry
}

func (o *ocspChecker) check(ctx context.Context, leaf, issuer *x509.Certificate) (RevocationStatus, error) {
	if leaf == nil || issuer == nil {
		err := &OCSPError{Kind: OCSPNoIssuer}
		o.emit(OCSPObservation{Status: RevocationUnknown, Err: err})
		return RevocationUnknown, err
	}
	id := sha256.Sum256(issuer.Raw)
	key := hex.EncodeToString(id[:8]) + ":" + leaf.SerialNumber.Text(16)
	o.mu.Lock()
	e, ok := o.cache[key]
	o.mu.Unlock()
	if ok && o.now().Before(e.expires) {
		o.emit(OCSPObservation{Status: e.status, Cached: true})
		return e.status, nil
	}
	// Нийт хугацаа (AIA-д олон URL байсан ч) — иргэн poll дээр хүлээж байна.
	actx, cancel := context.WithTimeout(ctx, ocspTotalTimeout)
	defer cancel()
	start := time.Now()
	status, resp, responder, err := o.ask(actx, leaf, issuer)
	took := time.Since(start)
	if err != nil {
		o.emit(OCSPObservation{Status: RevocationUnknown, Responder: responder, Duration: took, Err: err})
		return RevocationUnknown, err
	}
	// Зөвхөн "good"-ийг кэшлэнэ: revoked эцсийн, unknown нь дөнгөж олгогдсон гэрчилгээг кэшийн хугацаанд түгжихгүй.
	// Хугацаа = min(CacheTTL, NextUpdate − now) — responder-ийн өөрийн хүчинтэй хугацаанаас хэтрэхгүй.
	if status == RevocationGood && o.ttl > 0 {
		now := o.now()
		exp := now.Add(o.ttl)
		if !resp.NextUpdate.IsZero() && resp.NextUpdate.Before(exp) {
			exp = resp.NextUpdate
		}
		if exp.After(now) {
			o.mu.Lock()
			if len(o.cache) >= ocspCacheMax {
				o.cache = map[string]ocspEntry{}
			}
			o.cache[key] = ocspEntry{status: status, expires: exp}
			o.mu.Unlock()
		}
	}
	o.emit(OCSPObservation{Status: status, Responder: responder, Duration: took})
	return status, nil
}

func (o *ocspChecker) emit(ob OCSPObservation) {
	if o.observe != nil {
		o.observe(ob)
	}
}

// ask — AIA-ийн URL-уудыг дарааллаар; хариулсан URL ба (алдаа бол) сүүлийн шалтгааныг буцаана.
func (o *ocspChecker) ask(ctx context.Context, leaf, issuer *x509.Certificate) (RevocationStatus, *ocsp.Response, string, error) {
	reqDER, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: stdcrypto.SHA1})
	if err != nil {
		return "", nil, "", &OCSPError{Kind: OCSPNoIssuer, Err: err}
	}
	var lastErr error = &OCSPError{Kind: OCSPNoResponder}
	responder := ""
	for _, raw := range leaf.OCSPServer {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			lastErr = &OCSPError{Kind: OCSPNoResponder, Err: fmt.Errorf("OCSP URL %q дэмжигдэхгүй", raw)}
			continue
		}
		responder = u.String()
		der, err := o.post(ctx, responder, reqDER)
		if err != nil {
			lastErr = err
			continue
		}
		resp, verr := o.verify(der, leaf, issuer)
		if verr != nil {
			verr.Responder = responder
			lastErr = verr
			continue
		}
		switch resp.Status {
		case ocsp.Good:
			return RevocationGood, resp, responder, nil
		default: // Revoked, Unknown (олгогч мэдэхгүй serial)
			return RevocationRevoked, resp, responder, nil
		}
	}
	return "", nil, responder, lastErr
}

func (o *ocspChecker) post(ctx context.Context, u string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, ocspTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, &OCSPError{Kind: OCSPNoResponder, Responder: u, Err: err}
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	res, err := o.http.Do(req)
	if err != nil {
		return nil, &OCSPError{Kind: netKind(ctx, err), Responder: u, Err: err}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, &OCSPError{Kind: OCSPHTTPStatus, Responder: u, HTTPStatus: res.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, ocspMaxBytes+1))
	if err != nil {
		return nil, &OCSPError{Kind: netKind(ctx, err), Responder: u, Err: err}
	}
	if len(raw) > ocspMaxBytes {
		return nil, &OCSPError{Kind: OCSPHTTPStatus, Responder: u, HTTPStatus: res.StatusCode, Err: errors.New("хариу хэт том")}
	}
	return raw, nil
}

// netKind — timeout (ctx / http.Client.Timeout / net.Error.Timeout) эсвэл бусад сүлжээний алдаа.
func netKind(ctx context.Context, err error) OCSPErrorKind {
	var te interface{ Timeout() bool }
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		(errors.As(err, &te) && te.Timeout()) {
		return OCSPTimeout
	}
	return OCSPNetwork
}

// ocspParseKind — x/crypto/ocsp-ийн алдааг ангилна: responseStatus амжилтгүй; гарын үсэг (хариуны эсвэл шигтгэсэн
// responder гэрчилгээний); өөр serial-ийн хариу; бусад нь задрахгүй.
func ocspParseKind(err error) OCSPErrorKind {
	var re ocsp.ResponseError
	if errors.As(err, &re) {
		return OCSPResponderStatus
	}
	var pe ocsp.ParseError
	if errors.As(err, &pe) {
		switch msg := string(pe); {
		case strings.HasPrefix(msg, "bad OCSP signature"), strings.HasPrefix(msg, "bad signature on embedded certificate"):
			return OCSPSignature
		case strings.HasPrefix(msg, "no response matching"):
			return OCSPInvalid
		}
	}
	return OCSPParse
}

func (o *ocspChecker) verify(der []byte, leaf, issuer *x509.Certificate) (*ocsp.Response, *OCSPError) {
	resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err != nil {
		return nil, &OCSPError{Kind: ocspParseKind(err), Err: err}
	}
	now := o.now()
	if rc := resp.Certificate; rc != nil && !bytes.Equal(rc.Raw, issuer.Raw) {
		ekuOK := false
		for _, u := range rc.ExtKeyUsage {
			ekuOK = ekuOK || u == x509.ExtKeyUsageOCSPSigning
		}
		if !ekuOK {
			return nil, &OCSPError{Kind: OCSPSignature, Err: errors.New("responder-ийн EKU OCSPSigning биш")}
		}
		if now.Before(rc.NotBefore) || now.After(rc.NotAfter) {
			return nil, &OCSPError{Kind: OCSPSignature, Err: errors.New("responder-ийн гэрчилгээ хугацаандаа биш")}
		}
	}
	if resp.SerialNumber == nil || resp.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		return nil, &OCSPError{Kind: OCSPInvalid, Err: errors.New("хариу өөр serial-ийн тухай")}
	}
	if resp.ThisUpdate.After(now.Add(ocspClockSkew)) || resp.ThisUpdate.Before(now.Add(-ocspMaxAge)) {
		return nil, &OCSPError{Kind: OCSPInvalid, Err: errors.New("thisUpdate хүлээн авах хүрээнээс гадуур")}
	}
	if !resp.NextUpdate.IsZero() && resp.NextUpdate.Before(now) {
		return nil, &OCSPError{Kind: OCSPInvalid, Err: errors.New("хариу хуучирсан (nextUpdate өнгөрсөн)")}
	}
	return resp, nil
}
