package pades

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// validate golden v4 — цуцлалтын нотолгооны тохирол/шинэлэг байдал (DSS, offline) ба гүн давхарласан PDF
// (README.md «v4»). Оролт бүр = golden/output/quartz-pdf13.pdf-ийн гарын үсгийн revision + ӨӨР DSS revision: иргэний
// (leaf) OCSP ба 04-ийн CRL-ийг сольсон/хассан, бусад (TSA, 04/03/02-ын) нотолгоо хэвээр. Шалгах цаг = manifest.time
// (T+30с), гарын үсгийн цаг (TSA) = T+1с, T = goldenTime.

func v4Cases() []vCase {
	in := func(name string) vCase {
		return vCase{Name: name, Input: "validate/input/" + name + ".pdf", Offline: true}
	}
	return []vCase{
		in("dss-ocsp-stale"),                 // good, thisUpdate = T−400 хоног, nextUpdate-гүй → indeterminate
		in("dss-ocsp-expired"),               // good, nextUpdate = T−1ц (гарын үсгийн өмнө дууссан) → indeterminate
		in("dss-ocsp-future"),                // good, thisUpdate = T+2ц (шалгах цагаас хойш) → indeterminate
		in("dss-ocsp-other-serial"),          // good, өөр serial → indeterminate
		in("dss-ocsp-other-issuer"),          // good, иргэний serial, CertID = 03-ийн нэр/түлхүүр (04 зурсан) → indeterminate
		in("dss-ocsp-revoked"),               // revoked T−1ц + цэвэр 04 CRL → invalid / revoked
		in("dss-ocsp-revoked-after-signing"), // revoked T+3с (TSA-аас хойш) → valid / revoked_after_signing
		in("dss-crl-revoked"),                // good OCSP + иргэнийг агуулсан 04 CRL → invalid / revoked (revoked давамгай)
		in("dss-crl-wrong-issuer"),           // OCSP-гүй, 04 CRL-гүй, 05-ийн (өөр eID олгогч) цэвэр CRL → indeterminate
		in("dss-crl-only"),                   // OCSP-гүй, цэвэр шинэ 04 CRL → valid
		in("dss-no-revocation"),              // OCSP-гүй, 04 CRL-гүй → indeterminate
		in("deep-nesting"),                   // Catalog-д 300 түвшний массив → PDF_INVALID
		in("deep-nesting-objstm"),            // FlateDecode ObjStm дотор 300 түвшин (xref stream) → PDF_INVALID
	}
}

// v4Inputs — v4 оролтууд (нэр → байт). Байгаа файлыг дахин бичихгүй (vUpdate).
func v4Inputs(t *testing.T, p *goldenPKI) map[string][]byte {
	t.Helper()
	base, err := os.ReadFile(filepath.Join(goldenDir, "output", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	ca05 := v4CA05(t, p)
	cit := p.citizen.cert
	T := goldenTime.UTC()
	day := 24 * time.Hour
	leafOCSP := func(hashIssuer *x509.Certificate, serial *big.Int, status int, this, next, revokedAt time.Time) []byte {
		out, err := ocsp.CreateResponse(hashIssuer, p.ca04.cert, ocsp.Response{Status: status, SerialNumber: serial,
			ThisUpdate: this, NextUpdate: next, RevokedAt: revokedAt, RevocationReason: ocsp.KeyCompromise, IssuerHash: crypto.SHA1}, p.ca04.key)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	crl := func(iss *gCert, revoked ...x509.RevocationListEntry) []byte {
		out, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(9), ThisUpdate: T.Add(-time.Hour),
			NextUpdate: T.Add(30 * day), RevokedCertificateEntries: revoked}, iss.cert, iss.key)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	good := func(this, next time.Time) []byte {
		return leafOCSP(p.ca04.cert, cit.SerialNumber, ocsp.Good, this, next, time.Time{})
	}
	fresh := T.Add(5 * time.Second)
	crl04 := crl(p.ca04)
	revokedEntry := x509.RevocationListEntry{SerialNumber: cit.SerialNumber, RevocationTime: T.Add(-2 * time.Hour)}
	v := func(leaf, crls []byte) []byte { return v4WithDSS(t, p, base, leaf, crls) }
	return map[string][]byte{
		"dss-ocsp-stale":                 v(good(T.Add(-400*day), time.Time{}), nil),
		"dss-ocsp-expired":               v(good(T.Add(-2*time.Hour), T.Add(-time.Hour)), nil),
		"dss-ocsp-future":                v(good(T.Add(2*time.Hour), T.Add(2*time.Hour+day)), nil),
		"dss-ocsp-other-serial":          v(leafOCSP(p.ca04.cert, big.NewInt(9999), ocsp.Good, fresh, fresh.Add(day), time.Time{}), nil),
		"dss-ocsp-other-issuer":          v(leafOCSP(p.ca03.cert, cit.SerialNumber, ocsp.Good, fresh, fresh.Add(day), time.Time{}), nil),
		"dss-ocsp-revoked":               v(leafOCSP(p.ca04.cert, cit.SerialNumber, ocsp.Revoked, fresh, fresh.Add(day), T.Add(-time.Hour)), crl04),
		"dss-ocsp-revoked-after-signing": v(leafOCSP(p.ca04.cert, cit.SerialNumber, ocsp.Revoked, fresh, fresh.Add(day), T.Add(3*time.Second)), nil),
		"dss-crl-revoked":                v(good(fresh, fresh.Add(day)), crl(p.ca04, revokedEntry)),
		"dss-crl-wrong-issuer":           v(nil, crl(ca05)),
		"dss-crl-only":                   v(nil, crl04),
		"dss-no-revocation":              v(nil, nil),
		"deep-nesting":                   v4DeepPDF(300, false),
		"deep-nesting-objstm":            v4DeepPDF(300, true),
	}
}

// v4WithDSS — base-ийн эхний гарын үсгийн revision дээр DSS-ийг дахин угсарна: иргэний OCSP ба 04-ийн CRL-ийг хасаад
// leafOCSP / crl (nil бол үгүй) нэмнэ; бусад нотолгоо, гэрчилгээ хэвээр.
func v4WithDSS(t *testing.T, p *goldenPKI, base, leafOCSP, crl []byte) []byte {
	t.Helper()
	raws, err := validate.Extract(base)
	if err != nil || len(raws) != 1 || raws[0].DSS == nil {
		t.Fatalf("base: %v", err)
	}
	signed := base[:raws[0].SignedEnd]
	sigs, _, _, err := scanSignatures(signed)
	if err != nil || len(sigs) != 1 || len(sigs[0].byteRange) != 4 {
		t.Fatalf("ByteRange: %v", err)
	}
	br := [4]int64(sigs[0].byteRange)
	contents, err := core.SignatureContents(signed, br)
	if err != nil {
		t.Fatal(err)
	}
	d := core.DSS{Certs: raws[0].DSS.Certs, Contents: contents}
	for _, der := range raws[0].DSS.OCSPs {
		if r, err := ocsp.ParseResponseForCert(der, p.citizen.cert, p.ca04.cert); err == nil && r.SerialNumber.Cmp(p.citizen.cert.SerialNumber) == 0 {
			continue
		}
		d.OCSPs = append(d.OCSPs, der)
	}
	for _, der := range raws[0].DSS.CRLs {
		if c, err := x509.ParseRevocationList(der); err == nil && bytes.Equal(c.RawIssuer, p.ca04.cert.RawSubject) {
			continue
		}
		d.CRLs = append(d.CRLs, der)
	}
	if leafOCSP != nil {
		d.OCSPs = append(d.OCSPs, leafOCSP)
	}
	if crl != nil {
		d.CRLs = append(d.CRLs, crl)
	}
	out, err := core.AppendDSS(signed, d)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// v4CA05 — өөр eID олгогч (тестийн «05», 03-аас): manifest.issuers-д орно. validate/pki/-д хадгална.
func v4CA05(t *testing.T, p *goldenPKI) *gCert {
	t.Helper()
	dir := filepath.Join(validateDir, "pki")
	certPath, keyPath := filepath.Join(dir, "05.pem"), filepath.Join(dir, "05.key.pem")
	if raw, err := os.ReadFile(certPath); err == nil { // #nosec G304 -- тест
		kraw, err := os.ReadFile(keyPath) // #nosec G304 -- тест
		if err != nil {
			t.Fatal(err)
		}
		cb, _ := pem.Decode(raw)
		kb, _ := pem.Decode(kraw)
		c, err1 := x509.ParseCertificate(cb.Bytes)
		k, err2 := x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		return &gCert{cert: c, key: k}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2005), NotBefore: p.ca04.cert.NotBefore, NotAfter: p.ca04.cert.NotAfter,
		Subject: pkix.Name{CommonName: "TEST ONLY Golden eID Mongolia Issuing CA 05", Country: []string{"MN"}},
		IsCA:    true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca03.cert, &key.PublicKey, p.ca03.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)                                 // #nosec G306 -- тест
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o644) // #nosec G306 -- ТЕСТИЙН түлхүүр
	c, _ := x509.ParseCertificate(der)
	return &gCert{cert: c, key: key}
}

// v4DeepPDF — depth түвшний `[[…]]` бүхий жижиг PDF: objstm=false бол Catalog-ийн /X-д (сонгодог xref), true бол
// FlateDecode ObjStm-ийн 2-р объектод (xref stream-ээр заасан, Catalog /X 2 0 R).
func v4DeepPDF(depth int, objstm bool) []byte {
	nest := append(bytes.Repeat([]byte("["), depth), bytes.Repeat([]byte("]"), depth)...)
	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n")
	off := map[int]int{}
	obj := func(n int, body string) {
		off[n] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", n, body)
	}
	if !objstm {
		obj(1, "<< /Type /Catalog /Pages 3 0 R /X "+string(nest)+" >>")
		obj(3, "<< /Type /Pages /Kids [] /Count 0 >>")
		x := b.Len()
		fmt.Fprintf(&b, "xref\n0 4\n0000000000 65535 f \n%010d 00000 n \n0000000000 65535 f \n%010d 00000 n \n", off[1], off[3])
		fmt.Fprintf(&b, "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", x)
		return b.Bytes()
	}
	obj(1, "<< /Type /Catalog /Pages 3 0 R /X 2 0 R >>")
	obj(3, "<< /Type /Pages /Kids [] /Count 0 >>")
	head := "2 0 "
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write(append([]byte(head), nest...))
	_ = zw.Close()
	off[4] = b.Len()
	fmt.Fprintf(&b, "4 0 obj\n<< /Type /ObjStm /N 1 /First %d /Filter /FlateDecode /Length %d >>\nstream\n", len(head), z.Len())
	b.Write(z.Bytes())
	b.WriteString("\nendstream\nendobj\n")
	// xref stream (5): /W [1 4 2], шахаагүй.
	row := func(typ byte, f2 uint32, f3 uint16) []byte {
		r := []byte{typ, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(r[1:5], f2)
		binary.BigEndian.PutUint16(r[5:7], f3)
		return r
	}
	off[5] = b.Len()
	var rows []byte
	rows = append(rows, row(0, 0, 65535)...)
	rows = append(rows, row(1, uint32(off[1]), 0)...) // #nosec G115 -- жижиг тестийн файл
	rows = append(rows, row(2, 4, 0)...)
	rows = append(rows, row(1, uint32(off[3]), 0)...) // #nosec G115
	rows = append(rows, row(1, uint32(off[4]), 0)...) // #nosec G115
	rows = append(rows, row(1, uint32(off[5]), 0)...) // #nosec G115
	fmt.Fprintf(&b, "5 0 obj\n<< /Type /XRef /Size 6 /W [1 4 2] /Root 1 0 R /Length %d >>\nstream\n", len(rows))
	b.Write(rows)
	fmt.Fprintf(&b, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", off[5])
	return b.Bytes()
}
