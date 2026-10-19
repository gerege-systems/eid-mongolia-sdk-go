package pades

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/eidcrypto"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// parseRoots — DER итгэлийн тулгуурууд; хоосон бол шигтгэсэн Mongolian National Root CA (01).
func parseRoots(ders [][]byte) ([]*x509.Certificate, error) {
	if len(ders) == 0 {
		return []*x509.Certificate{eidcrypto.NationalRoot()}, nil
	}
	return parseDERs(ders)
}

func parseDERs(ders [][]byte) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(ders))
	for i, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, fmt.Errorf("гэрчилгээ #%d: %w", i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// signerChain — өгсөн гинж (DER, 04/03/02) эсвэл шигтгэсэн eID гинжээс signer-ийн олгогчоор root хүртэл (root-гүй).
func signerChain(signer *x509.Certificate, ders [][]byte) ([]*x509.Certificate, error) {
	if len(ders) > 0 {
		return parseDERs(ders)
	}
	pool := eidcrypto.Intermediates()
	var chain []*x509.Certificate
	cur := signer
	for range len(pool) + 1 {
		var next *x509.Certificate
		for _, c := range pool {
			if bytes.Equal(c.RawSubject, cur.RawIssuer) && cur.CheckSignatureFrom(c) == nil {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		chain = append(chain, next)
		cur = next
	}
	if len(chain) == 0 {
		return nil, errors.New("signer-ийн олгогч шигтгэсэн eID гинжид алга — chain өгнө үү")
	}
	return chain, nil
}

// newValidator — CA-ийн нийтийн шалгагчийн тохиргоо: root = roots, завсрын = шигтгэсэн 02–05 + extra, eID олгогч =
// шигтгэсэн 04/05 + extraIssuers, цуцлалт = баримтын DSS (CA өөрийн DB-ээс уншдаг — клиентэд DB алга, §dssStatus).
// raws өгвөл Extract-ийг дахин хийхгүй.
func newValidator(roots, extra, extraIssuers []*x509.Certificate, now func() time.Time, raws []validate.RawSignature) *validate.Validator {
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	issuers := append(eidcrypto.Issuers(), extraIssuers...)
	v := &validate.Validator{
		Roots:         pool,
		Intermediates: append(eidcrypto.Intermediates(), extra...),
		Issuers:       issuers,
		Now:           now,
	}
	if raws != nil {
		v.Extract = func(context.Context, []byte) ([]validate.RawSignature, error) { return raws, nil }
		v.Status = newDSSStatus(raws, now)
	}
	return v
}

// dssStatus — validate.StatusSource: eID олгогчийн (04/05) гаргасан гэрчилгээний цуцлалтыг баримтын DSS-ийн
// OCSP/CRL-ээс уншина. Нотолгоо нь ЭНЭ гэрчилгээ + түүний гинжийн олгогчийнх байх ёстой: OCSP — олгогч (эсвэл
// түүний OCSPSigning responder) зурсан, CertID = олгогчийн нэр/түлхүүрийн hash + serial; CRL — олгогчийн нэр (AKI),
// олгогчийн гарын үсэг. Цуцалсан нотолгоо аль нэг нь байвал revoked (шинэлэг эсэхээс үл хамааран — цуцлалт буцахгүй,
// «good» нотолгоог давна); үгүй бол at-д шинэлэг (validate.FreshAt) good нотолгоо байвал good; эс бөгөөс
// Issued=false («unknown» → revocation_unavailable — таамаглахгүй). Гарын үсгийн дараах цуцлалтыг
// (revoked_after_signing) зөвхөн DSS-д байвал мэднэ.
type dssStatus struct {
	ocsps [][]byte
	crls  [][]byte
	now   func() time.Time
}

func newDSSStatus(raws []validate.RawSignature, now func() time.Time) *dssStatus {
	if now == nil {
		now = time.Now
	}
	s := &dssStatus{now: now}
	for _, r := range raws {
		if r.DSS != nil {
			s.ocsps, s.crls = r.DSS.OCSPs, r.DSS.CRLs
			break
		}
	}
	return s
}

func (s *dssStatus) CertStatus(cert, issuer *x509.Certificate, at time.Time) (validate.CertStatus, error) {
	now := s.now()
	var revoked *time.Time
	markRevoked := func(t time.Time) {
		if revoked == nil || t.Before(*revoked) {
			revoked = &t
		}
	}
	good := false
	for _, der := range s.ocsps {
		resp, ok := ocspFor(der, cert, issuer)
		if !ok {
			continue
		}
		switch resp.Status {
		case ocsp.Revoked:
			markRevoked(resp.RevokedAt)
		case ocsp.Good:
			good = good || validate.FreshAt(resp.ThisUpdate, resp.NextUpdate, at, now)
		}
	}
	for _, der := range s.crls {
		crl, err := x509.ParseRevocationList(der)
		if err != nil || !validate.CRLFor(crl, cert, issuer) {
			continue
		}
		if t, listed := validate.CRLListed(crl, cert); listed {
			markRevoked(t)
		} else {
			good = good || validate.FreshAt(crl.ThisUpdate, crl.NextUpdate, at, now)
		}
	}
	switch {
	case revoked != nil:
		return validate.CertStatus{Issued: true, Revoked: true, RevokedAt: *revoked}, nil
	case good:
		return validate.CertStatus{Issued: true}, nil
	}
	return validate.CertStatus{}, nil
}

// ocspFor — der нь cert-ийн (CertID = issuer + serial) хариу, олгогч эсвэл түүний OCSPSigning responder зурсан.
func ocspFor(der []byte, cert, issuer *x509.Certificate) (*ocsp.Response, bool) {
	resp, err := parseOCSPFrom(der, cert, issuer)
	if err != nil || resp.SerialNumber == nil || resp.SerialNumber.Cmp(cert.SerialNumber) != 0 ||
		!validate.OCSPCertIDMatches(der, cert, issuer) || !responderOK(resp, issuer) {
		return nil, false
	}
	return resp, true
}

// responderOK — OCSP хариуг олгогч өөрөө, эсвэл олгогчийн гаргасан id-kp-OCSPSigning EKU-тэй responder зурсан.
func responderOK(resp *ocsp.Response, issuer *x509.Certificate) bool {
	if resp.Certificate == nil || resp.Certificate.Equal(issuer) {
		return true
	}
	return slices.Contains(resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
}
