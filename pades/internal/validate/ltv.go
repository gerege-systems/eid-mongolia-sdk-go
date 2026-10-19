package validate

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"
)

// subFilterCAdES — PAdES baseline-ийн SubFilter (internal/pdfsign/pades).
const subFilterCAdES = "ETSI.CAdES.detached"

// oidOCSPNoCheck — id-pkix-ocsp-nocheck: delegated OCSP responder-ийн cert-д цуцлалт шалгахгүй (RFC 6960).
var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// ltvCoverage — гарын үсгийн гинж (leaf → root) ба TSA гинжийн root-оос бусад гэрчилгээ бүрд DSS-д
// олгогчоор (эсвэл түүний delegated responder-оор, id-pkix-ocsp-nocheck-тэй) зурагдсан, `good`, шинэлэг OCSP
// эсвэл олгогчийн зурсан, тэр гэрчилгээг агуулаагүй, at-ийг хамарсан CRL байх ёстой. Итгэлийн шийдвэр биш
// (indication-д нөлөөлөхгүй) — finalize-ийн self-check ба мэдээлэлд.
//
// Шинэлэг байдал = FreshAt (thisUpdate ≥ at − RevocationMaxAge, эсвэл thisUpdate…nextUpdate нь at-ийг хамарна — 03-ийн
// урьдчилан гаргасан OCSP, CRL); now — шалгагчийн одоо (ирээдүйн thisUpdate-ийг татгалзана).
func ltvCoverage(dss *RawDSS, at, now time.Time, chains ...[]*x509.Certificate) *LTVInfo {
	out := &LTVInfo{Missing: []string{}}
	var ocsps []([]byte)
	var crls []*x509.RevocationList
	if dss != nil {
		ocsps = dss.OCSPs
		for _, der := range dss.CRLs {
			if c, err := x509.ParseRevocationList(der); err == nil {
				crls = append(crls, c)
			}
		}
	}
	seen := map[string]bool{}
	for _, chain := range chains {
		for i := 0; i+1 < len(chain); i++ {
			cert, issuer := chain[i], chain[i+1]
			if seen[string(cert.Raw)] {
				continue
			}
			seen[string(cert.Raw)] = true
			if !covered(cert, issuer, at, now, ocsps, crls) {
				out.Missing = append(out.Missing, cert.Subject.CommonName)
			}
		}
	}
	out.Complete = len(out.Missing) == 0 && len(seen) > 0
	return out
}

func covered(cert, issuer *x509.Certificate, at, now time.Time, ocsps [][]byte, crls []*x509.RevocationList) bool {
	for _, der := range ocsps {
		resp, err := ocsp.ParseResponseForCert(der, cert, issuer)
		if err != nil || resp.Status != ocsp.Good || !OCSPCertIDMatches(der, cert, issuer) {
			continue
		}
		// Delegated responder: олгогчийн гаргасан, nocheck-тэй байх ёстой (ParseResponse гарын үсэг ба EKU-г шалгасан).
		if resp.Certificate != nil && !bytes.Equal(resp.Certificate.Raw, issuer.Raw) &&
			!slices.ContainsFunc(resp.Certificate.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oidOCSPNoCheck) }) {
			continue
		}
		if FreshAt(resp.ThisUpdate, resp.NextUpdate, at, now) {
			return true
		}
	}
	for _, crl := range crls {
		if !CRLFor(crl, cert, issuer) || !FreshAt(crl.ThisUpdate, crl.NextUpdate, at, now) {
			continue
		}
		if _, listed := CRLListed(crl, cert); listed {
			continue
		}
		return true
	}
	return false
}
