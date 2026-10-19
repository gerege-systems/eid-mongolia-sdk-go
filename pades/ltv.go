package pades

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"context"

	"golang.org/x/crypto/ocsp"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// DSS (B-LT) цуглуулалт — CA-ийн service/memory/pades_ltv.go padesLTV-ийн сүлжээний хувилбар: CA in-process
// responder/кэшээс уншдаг бол энд гэрчилгээ бүрийн AIA OCSP (SHA-1 CertID) ба CDP CRL-ийг татна. Гарын үсэг/олгогч,
// CertID, шинэлэг байдал (validate.FreshAt, одоогийн цагаар) шалгана; аль нэг гэрчилгээнд хүчинтэй мэдээлэл алга бол
// алдаа (fail-closed). Олгогчийн гарын үсэгтэй «revoked» хариу (OCSP эсвэл CRL) — ErrCertificateRevoked, тэр дор нь
// зогсоно (өөр URL/CRL-ээр «good» хайхгүй, дахин оролдохгүй).

var (
	errLTV      = errors.New("LTV өгөгдөл бүрэн биш")
	errNotFresh = errors.New("OCSP thisUpdate нь timestamp-аас хожуу биш")
)

// ocspAfterTS / ocspWaitMax — CA padesOCSPAfterTS / padesOCSPWaitMax: genTime-ийн секундын эхнээс 2 с хүлээж асууна,
// thisUpdate хангалтгүй бол 1 с тутам дахин, нийт хүлээлт ≤ 5 с.
const (
	ocspAfterTS = 2 * time.Second
	ocspWaitMax = 5 * time.Second
	ocspRetry   = time.Second
)

// sleepFn — тестэд солино.
var sleepFn = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// collectLTVWithWait — genTime-ийн дараах OCSP-г хүлээж (≤ 5 с), freshness-ийн алдаанд дахин оролдоно.
func collectLTVWithWait(ctx context.Context, f *fetcher, now func() time.Time, genTime time.Time, roots []*x509.Certificate, chains ...[]*x509.Certificate) (core.DSS, error) {
	waited := time.Duration(0)
	d := min(genTime.Truncate(time.Second).Add(ocspAfterTS).Sub(now()), ocspWaitMax)
	for {
		if d > 0 {
			if err := sleepFn(ctx, d); err != nil {
				return core.DSS{}, err
			}
			waited += d
		}
		dss, err := collectLTV(ctx, f, now(), genTime, roots, chains...)
		if err == nil || !errors.Is(err, errNotFresh) || waited+ocspRetry > ocspWaitMax {
			return dss, err
		}
		d = ocspRetry
	}
}

// collectLTV — chains (leaf → … root-оос өмнөх) бүрийн гэрчилгээнд DSS өгөгдөл. after (тэг биш) — гинжийн leaf-ийн
// (иргэн, TSA) OCSP thisUpdate үүнээс хожуу байх ёстой (CA: 04-ийн олгосон cert-д).
func collectLTV(ctx context.Context, f *fetcher, now, after time.Time, roots []*x509.Certificate, chains ...[]*x509.Certificate) (core.DSS, error) {
	var d core.DSS
	addCert := func(c *x509.Certificate) {
		if !slices.ContainsFunc(d.Certs, func(b []byte) bool { return bytes.Equal(b, c.Raw) }) {
			d.Certs = append(d.Certs, c.Raw)
		}
	}
	add := func(list *[][]byte, der []byte) {
		if !slices.ContainsFunc(*list, func(b []byte) bool { return bytes.Equal(b, der) }) {
			*list = append(*list, der)
		}
	}
	var pool []*x509.Certificate
	for _, ch := range chains {
		pool = append(pool, ch...)
	}
	issuerOf := func(c *x509.Certificate) *x509.Certificate {
		for _, cand := range append(append([]*x509.Certificate{}, pool...), roots...) {
			if bytes.Equal(cand.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(cand) == nil {
				return cand
			}
		}
		return nil
	}
	isRoot := func(c *x509.Certificate) bool {
		return slices.ContainsFunc(roots, func(r *x509.Certificate) bool { return r.Equal(c) })
	}
	seen := map[string]bool{}
	for _, ch := range chains {
		for i, c := range ch {
			if seen[string(c.Raw)] || isRoot(c) {
				continue
			}
			seen[string(c.Raw)] = true
			addCert(c)
			issuer := issuerOf(c)
			if issuer == nil {
				return core.DSS{}, fmt.Errorf("%w: %s-ийн олгогч олдсонгүй", errLTV, certRef(c))
			}
			ok := false
			var freshErr error
			fresh := time.Time{}
			if i == 0 {
				fresh = after
			}
			for _, u := range c.OCSPServer {
				der, resp, err := fetchOCSP(ctx, f, u, c, issuer, now, fresh)
				if errors.Is(err, ErrCertificateRevoked) {
					return core.DSS{}, fmt.Errorf("%w: %s", err, certRef(c))
				}
				if errors.Is(err, errNotFresh) {
					freshErr = err
				}
				if err != nil {
					continue
				}
				add(&d.OCSPs, der)
				if resp.Certificate != nil && !resp.Certificate.Equal(issuer) {
					addCert(resp.Certificate) // delegated responder
				}
				ok = true
				break
			}
			for _, u := range c.CRLDistributionPoints {
				der, err := f.do(ctx, http.MethodGet, u, "", nil)
				if err != nil {
					continue
				}
				covers, err := crlCovers(der, c, issuer, now)
				if err != nil {
					return core.DSS{}, fmt.Errorf("%w: %s", err, certRef(c))
				}
				if covers {
					add(&d.CRLs, der)
					ok = true
				}
			}
			if !ok {
				if freshErr != nil {
					return core.DSS{}, fmt.Errorf("%w: %s", freshErr, certRef(c))
				}
				return core.DSS{}, fmt.Errorf("%w: %s-д хүчинтэй OCSP/CRL алга", errLTV, certRef(c))
			}
			if i == 0 && !after.IsZero() && freshErr != nil && len(c.OCSPServer) > 0 && !hasFreshOCSP(d.OCSPs, c, issuer, after) {
				// Leaf-ийн OCSP нь genTime-ээс хожуу биш — CRL байсан ч CA-ийн дүрмээр дахин оролдоно.
				return core.DSS{}, fmt.Errorf("%w: %s", freshErr, certRef(c))
			}
		}
	}
	return d, nil
}

// certRef — алдааны текстэд гэрчилгээг нэрээр (CN = иргэний овог нэр, PII) биш serial-аар заана.
func certRef(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		return "serial ?"
	}
	return "serial " + c.SerialNumber.Text(16)
}

func hasFreshOCSP(list [][]byte, c, issuer *x509.Certificate, after time.Time) bool {
	for _, der := range list {
		if r, err := ocsp.ParseResponseForCert(der, c, issuer); err == nil && r.ThisUpdate.After(after) && validate.OCSPCertIDMatches(der, c, issuer) {
			return true
		}
	}
	return false
}

// fetchOCSP — CA padesOCSP: SHA-1 CertID (RFC 5019) = энэ гэрчилгээ + олгогч, олгогч (эсвэл delegated) зурсан, good,
// одоо шинэлэг (validate.FreshAt), after тэг биш бол thisUpdate > after. revoked → ErrCertificateRevoked.
func fetchOCSP(ctx context.Context, f *fetcher, url string, c, issuer *x509.Certificate, now, after time.Time) ([]byte, *ocsp.Response, error) {
	req, err := ocsp.CreateRequest(c, issuer, &ocsp.RequestOptions{Hash: stdcrypto.SHA1})
	if err != nil {
		return nil, nil, err
	}
	der, err := f.do(ctx, http.MethodPost, url, "application/ocsp-request", req)
	if err != nil {
		return nil, nil, err
	}
	resp, err := ocsp.ParseResponseForCert(der, c, issuer)
	if err != nil {
		return nil, nil, err
	}
	if !responderOK(resp, issuer) {
		return nil, nil, errors.New("OCSP responder-ийн EKU OCSPSigning биш")
	}
	if !validate.OCSPCertIDMatches(der, c, issuer) {
		return nil, nil, errors.New("OCSP CertID энэ гэрчилгээ/олгогчийнх биш")
	}
	if resp.Status == ocsp.Revoked {
		return nil, nil, ErrCertificateRevoked
	}
	if resp.Status != ocsp.Good || !validate.FreshAt(resp.ThisUpdate, resp.NextUpdate, now, now) {
		return nil, nil, fmt.Errorf("OCSP %s: status %d", certRef(c), resp.Status)
	}
	if !after.IsZero() && !resp.ThisUpdate.After(after) {
		return nil, nil, errNotFresh
	}
	return der, resp, nil
}

// crlCovers — der нь c-ийн олгогчийн (нэр/AKI, гарын үсэг шалгасан) CRL, nextUpdate-тэй, одоо шинэлэг
// (validate.FreshAt), c-г агуулаагүй. c жагсаалтад байвал ErrCertificateRevoked.
func crlCovers(der []byte, c, issuer *x509.Certificate, now time.Time) (bool, error) {
	crl, err := x509.ParseRevocationList(der)
	if err != nil || !validate.CRLFor(crl, c, issuer) {
		return false, nil
	}
	if _, listed := validate.CRLListed(crl, c); listed {
		return false, ErrCertificateRevoked
	}
	return !crl.NextUpdate.IsZero() && validate.FreshAt(crl.ThisUpdate, crl.NextUpdate, now, now), nil
}
