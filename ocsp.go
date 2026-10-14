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
//   - good → RevocationGood (5 мин кэшлэнэ);
//   - revoked, мөн unknown (олгогч энэ serial-ийг олгоогүй — өөр хэн нэгний хийсэн гэрчилгээ) → RevocationRevoked;
//   - хариугүй (AIA алга, issuer олдоогүй, timeout, 5xx, гарын үсэг/serial/хугацаа таараагүй хариу) → RevocationUnknown,
//     nil. Validator-ийн RevocationMode шийднэ: soft-fail — зөвшөөрнө (unchecked), hard-fail — татгалзана.
//
// Хариуг олгогч эсвэл олгогчийн id-kp-OCSPSigning EKU-тэй (одоо хүчинтэй) responder зурсан, энэ serial-ийн тухай,
// thisUpdate нь [now−48ц, now+5мин], nextUpdate өнгөрөөгүй байх ёстой.
func NewOCSPChecker(opts OCSPOptions) RevocationChecker {
	o := &ocspChecker{http: opts.HTTPClient, now: opts.Now, cache: map[string]ocspEntry{}}
	if o.http == nil {
		o.http = &http.Client{Timeout: ocspTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	if o.now == nil {
		o.now = time.Now
	}
	return o.check
}

type ocspChecker struct {
	http *http.Client
	now  func() time.Time

	mu    sync.Mutex
	cache map[string]ocspEntry
}

func (o *ocspChecker) check(ctx context.Context, leaf, issuer *x509.Certificate) (RevocationStatus, error) {
	if leaf == nil || issuer == nil {
		return RevocationUnknown, nil
	}
	id := sha256.Sum256(issuer.Raw)
	key := hex.EncodeToString(id[:8]) + ":" + leaf.SerialNumber.Text(16)
	o.mu.Lock()
	e, ok := o.cache[key]
	o.mu.Unlock()
	if ok && o.now().Before(e.expires) {
		return e.status, nil
	}
	// Нийт хугацаа (AIA-д олон URL байсан ч) — иргэн poll дээр хүлээж байна.
	actx, cancel := context.WithTimeout(ctx, ocspTotalTimeout)
	defer cancel()
	status, err := o.ask(actx, leaf, issuer)
	if err != nil {
		return RevocationUnknown, nil
	}
	// Зөвхөн "good"-ийг кэшлэнэ: revoked эцсийн, unknown нь дөнгөж олгогдсон гэрчилгээг кэшийн хугацаанд түгжихгүй.
	if status == RevocationGood {
		o.mu.Lock()
		if len(o.cache) >= ocspCacheMax {
			o.cache = map[string]ocspEntry{}
		}
		o.cache[key] = ocspEntry{status: status, expires: o.now().Add(ocspCacheTTL)}
		o.mu.Unlock()
	}
	return status, nil
}

func (o *ocspChecker) ask(ctx context.Context, leaf, issuer *x509.Certificate) (RevocationStatus, error) {
	reqDER, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: stdcrypto.SHA1})
	if err != nil {
		return "", err
	}
	lastErr := errors.New("гэрчилгээнд OCSP responder алга")
	for _, raw := range leaf.OCSPServer {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			lastErr = fmt.Errorf("OCSP URL %q дэмжигдэхгүй", raw)
			continue
		}
		der, err := o.post(ctx, u.String(), reqDER)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := o.verify(der, leaf, issuer)
		if err != nil {
			lastErr = err
			continue
		}
		switch resp.Status {
		case ocsp.Good:
			return RevocationGood, nil
		default: // Revoked, Unknown (олгогч мэдэхгүй serial)
			return RevocationRevoked, nil
		}
	}
	return "", lastErr
}

func (o *ocspChecker) post(ctx context.Context, u string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, ocspTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	res, err := o.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP HTTP %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, ocspMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > ocspMaxBytes {
		return nil, errors.New("OCSP хариу хэт том")
	}
	return raw, nil
}

func (o *ocspChecker) verify(der []byte, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err != nil {
		return nil, err
	}
	now := o.now()
	if rc := resp.Certificate; rc != nil && !bytes.Equal(rc.Raw, issuer.Raw) {
		ekuOK := false
		for _, u := range rc.ExtKeyUsage {
			ekuOK = ekuOK || u == x509.ExtKeyUsageOCSPSigning
		}
		if !ekuOK {
			return nil, errors.New("OCSP responder-ийн EKU OCSPSigning биш")
		}
		if now.Before(rc.NotBefore) || now.After(rc.NotAfter) {
			return nil, errors.New("OCSP responder-ийн гэрчилгээ хугацаандаа биш")
		}
	}
	if resp.SerialNumber == nil || resp.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		return nil, errors.New("OCSP хариу өөр serial-ийн тухай")
	}
	if resp.ThisUpdate.After(now.Add(ocspClockSkew)) || resp.ThisUpdate.Before(now.Add(-ocspMaxAge)) {
		return nil, errors.New("OCSP thisUpdate хүлээн авах хүрээнээс гадуур")
	}
	if !resp.NextUpdate.IsZero() && resp.NextUpdate.Before(now) {
		return nil, errors.New("OCSP хариу хуучирсан (nextUpdate өнгөрсөн)")
	}
	return resp, nil
}
