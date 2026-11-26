package validate

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"sync"
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
	seen := map[string]bool{}
	for _, chain := range chains {
		for i := 0; i+1 < len(chain); i++ {
			cert, issuer := chain[i], chain[i+1]
			if seen[string(cert.Raw)] {
				continue
			}
			seen[string(cert.Raw)] = true
			if dss == nil || !covered(dss, cert, issuer, at, now) {
				out.Missing = append(out.Missing, cert.Subject.CommonName)
			}
		}
	}
	out.Complete = len(out.Missing) == 0 && len(seen) > 0
	return out
}

func covered(dss *RawDSS, cert, issuer *x509.Certificate, at, now time.Time) bool {
	for i, der := range dss.OCSPs {
		resp := dss.ocspPlain(i, cert, issuer)
		if resp == nil || resp.Status != ocsp.Good || !OCSPCertIDMatches(der, cert, issuer) {
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
	for i := range dss.CRLs {
		if !dss.CRLMatches(i, cert, issuer) {
			continue
		}
		crl := dss.CRL(i)
		if !FreshAt(crl.ThisUpdate, crl.NextUpdate, at, now) {
			continue
		}
		if _, listed := CRLListed(crl, cert); listed {
			continue
		}
		return true
	}
	return false
}

// dssCache — RawDSS-ийн OCSP/CRL-ийг нэг шалгалтад нэг удаа задалж, (нотолгоо, гэрчилгээ, олгогч) бүрийн гарын үсгийн
// шалгалтыг нэг удаа хийнэ: олон гарын үсэг × гинж × DSS-ийн мөрийн давталтаар ажил өсөхгүй.
type dssCache struct {
	mu     sync.Mutex
	crls   []*x509.RevocationList // nil — задраагүй
	parsed bool
	ocsp   map[dssKey]*ocsp.Response
	crlFor map[dssKey]bool
}

type dssKey struct {
	i            int
	cert, issuer string
}

func (d *RawDSS) cacheFor() *dssCache {
	d.cacheOnce.Do(func() {
		d.cache = &dssCache{ocsp: map[dssKey]*ocsp.Response{}, crlFor: map[dssKey]bool{}}
	})
	return d.cache
}

// CRL — CRLs[i]-ийн задалсан хэлбэр (нэг удаа); задрахгүй бол nil.
func (d *RawDSS) CRL(i int) *x509.RevocationList {
	c := d.cacheFor()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.parsed {
		c.crls = make([]*x509.RevocationList, len(d.CRLs))
		for k, der := range d.CRLs {
			if l, err := x509.ParseRevocationList(der); err == nil {
				c.crls[k] = l
			}
		}
		c.parsed = true
	}
	return c.crls[i]
}

// CRLMatches — CRLFor(CRL(i), cert, issuer) (олгогчийн гарын үсгийн шалгалт) нэг удаа; задрахгүй бол false.
func (d *RawDSS) CRLMatches(i int, cert, issuer *x509.Certificate) bool {
	crl := d.CRL(i)
	if crl == nil {
		return false
	}
	c := d.cacheFor()
	k := dssKey{i, string(cert.Raw), string(issuer.Raw)}
	c.mu.Lock()
	ok, hit := c.crlFor[k]
	c.mu.Unlock()
	if hit {
		return ok
	}
	ok = CRLFor(crl, cert, issuer)
	c.mu.Lock()
	c.crlFor[k] = ok
	c.mu.Unlock()
	return ok
}

// ocspPlain — ocsp.ParseResponseForCert(OCSPs[i], cert, issuer) нэг удаа; алдаа бол nil.
func (d *RawDSS) ocspPlain(i int, cert, issuer *x509.Certificate) *ocsp.Response {
	c := d.cacheFor()
	k := dssKey{i, string(cert.Raw), string(issuer.Raw)}
	c.mu.Lock()
	r, hit := c.ocsp[k]
	c.mu.Unlock()
	if hit {
		return r
	}
	r, err := ocsp.ParseResponseForCert(d.OCSPs[i], cert, issuer)
	if err != nil {
		r = nil
	}
	c.mu.Lock()
	c.ocsp[k] = r
	c.mu.Unlock()
	return r
}
