package pades

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
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
		v.Status = newDSSStatus(raws, issuers, roots)
	}
	return v
}

// dssStatus — validate.StatusSource: eID олгогчийн (04/05) гаргасан гэрчилгээний цуцлалтыг баримтын DSS-ийн
// OCSP/CRL-ээс (олгогчийн гарын үсгээр шалгасан) уншина. Нотолгоо олдохгүй бол Issued=false («unknown» —
// таамаглахгүй). Гарын үсгийн дараах цуцлалтыг (revoked_after_signing) зөвхөн DSS-д байвал мэднэ.
type dssStatus struct {
	ocsps   [][]byte
	crls    [][]byte
	issuers []*x509.Certificate
}

func newDSSStatus(raws []validate.RawSignature, issuers, _ []*x509.Certificate) *dssStatus {
	s := &dssStatus{issuers: issuers}
	for _, r := range raws {
		if r.DSS != nil {
			s.ocsps, s.crls = r.DSS.OCSPs, r.DSS.CRLs
			break
		}
	}
	return s
}

func (s *dssStatus) CertStatus(serial *big.Int) (validate.CertStatus, error) {
	for _, der := range s.ocsps {
		for _, iss := range s.issuers {
			resp, err := parseOCSPFrom(der, nil, iss)
			if err != nil || resp.SerialNumber == nil || resp.SerialNumber.Cmp(serial) != 0 || !responderOK(resp, iss) {
				continue
			}
			switch resp.Status {
			case ocsp.Good:
				return validate.CertStatus{Issued: true}, nil
			case ocsp.Revoked:
				return validate.CertStatus{Issued: true, Revoked: true, RevokedAt: resp.RevokedAt}, nil
			}
		}
	}
	for _, der := range s.crls {
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			continue
		}
		for _, iss := range s.issuers {
			if !bytes.Equal(crl.RawIssuer, iss.RawSubject) || crl.CheckSignatureFrom(iss) != nil {
				continue
			}
			for _, e := range crl.RevokedCertificateEntries {
				if e.SerialNumber.Cmp(serial) == 0 {
					return validate.CertStatus{Issued: true, Revoked: true, RevokedAt: e.RevocationTime}, nil
				}
			}
			return validate.CertStatus{Issued: true}, nil
		}
	}
	return validate.CertStatus{}, nil
}

// responderOK — OCSP хариуг олгогч өөрөө, эсвэл олгогчийн гаргасан id-kp-OCSPSigning EKU-тэй responder зурсан.
func responderOK(resp *ocsp.Response, issuer *x509.Certificate) bool {
	if resp.Certificate == nil || resp.Certificate.Equal(issuer) {
		return true
	}
	return slices.Contains(resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
}
