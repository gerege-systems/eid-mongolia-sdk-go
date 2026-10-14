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

// ltvFreshness — OCSP-ийн thisUpdate нь гарын үсгийн цагаас хамгийн ихдээ ийм хугацаагаар өмнө байж болно
// (§8.3); эсвэл хариуны хүчинтэй хугацаа (thisUpdate…nextUpdate) гарын үсгийн цагийг хамарна (03-ийн
// урьдчилан гаргасан OCSP, CRL).
const ltvFreshness = 24 * time.Hour

// oidOCSPNoCheck — id-pkix-ocsp-nocheck: delegated OCSP responder-ийн cert-д цуцлалт шалгахгүй (RFC 6960).
var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// ltvCoverage — гарын үсгийн гинж (leaf → root) ба TSA гинжийн root-оос бусад гэрчилгээ бүрд DSS-д
// олгогчоор (эсвэл түүний delegated responder-оор, id-pkix-ocsp-nocheck-тэй) зурагдсан, `good`, шинэлэг OCSP
// эсвэл олгогчийн зурсан, тэр гэрчилгээг агуулаагүй, at-ийг хамарсан CRL байх ёстой. Итгэлийн шийдвэр биш
// (indication-д нөлөөлөхгүй) — finalize-ийн self-check ба мэдээлэлд.
func ltvCoverage(dss *RawDSS, at time.Time, chains ...[]*x509.Certificate) *LTVInfo {
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
			if !covered(cert, issuer, at, ocsps, crls) {
				out.Missing = append(out.Missing, cert.Subject.CommonName)
			}
		}
	}
	out.Complete = len(out.Missing) == 0 && len(seen) > 0
	return out
}

func covered(cert, issuer *x509.Certificate, at time.Time, ocsps [][]byte, crls []*x509.RevocationList) bool {
	for _, der := range ocsps {
		resp, err := ocsp.ParseResponseForCert(der, cert, issuer)
		if err != nil || resp.Status != ocsp.Good {
			continue
		}
		// Delegated responder: олгогчийн гаргасан, nocheck-тэй байх ёстой (ParseResponse гарын үсэг ба EKU-г шалгасан).
		if resp.Certificate != nil && !bytes.Equal(resp.Certificate.Raw, issuer.Raw) &&
			!slices.ContainsFunc(resp.Certificate.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oidOCSPNoCheck) }) {
			continue
		}
		if !resp.ThisUpdate.Before(at.Add(-ltvFreshness)) ||
			!resp.NextUpdate.IsZero() && !resp.NextUpdate.Before(at) && !resp.ThisUpdate.After(at) {
			return true
		}
	}
	for _, crl := range crls {
		if !bytes.Equal(crl.RawIssuer, cert.RawIssuer) || crl.CheckSignatureFrom(issuer) != nil {
			continue
		}
		if !crl.NextUpdate.IsZero() && crl.NextUpdate.Before(at) {
			continue
		}
		if slices.ContainsFunc(crl.RevokedCertificateEntries, func(e x509.RevocationListEntry) bool {
			return e.SerialNumber.Cmp(cert.SerialNumber) == 0
		}) {
			continue
		}
		return true
	}
	return false
}
