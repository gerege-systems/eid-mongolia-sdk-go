package pades

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gerege-systems/pdf"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// ValidatePDF hardening (pades/testdata/validate v14, README «v14»): two independent reviews of the .NET/Java ports found
// weaknesses in the reference validators. Every case is offline; inputs are written once by -update (existing files are
// never rewritten).
func hardeningVCases() []vCase {
	return []vCase{
		// A. Shadow attack: an object of the signed revision whose stream /Length runs past the signed bytes, completed by a
		// later DSS-only revision. Control: the same pipeline with a complete object.
		{Name: "shadow-stream-dss", Input: "validate/input/shadow-stream-dss.pdf", Offline: true},
		{Name: "shadow-control", Input: "validate/input/shadow-control.pdf", Offline: true},
		// B. Later-signature trust: a later revision whose signature fails integrity. A later visible stamp whose /Name is
		// not the signing certificate's display name is accepted since v15 (the name is not compared); control with the
		// matching name.
		{Name: "later-sig-integrity-failed", Input: "validate/input/later-sig-integrity-failed.pdf", Offline: true},
		{Name: "later-stamp-name-mismatch", Input: "validate/input/later-stamp-name-mismatch.pdf", Offline: true},
		{Name: "later-stamp-name-control", Input: "validate/input/later-stamp-name-control.pdf", Offline: true},
		// C. platform_attested only for unmodified documents (doc-signer certificate, legacy CA stamp profile).
		{Name: "doc-signer-attested", Input: "validate/input/doc-signer-attested.pdf", Offline: true},
		{Name: "doc-signer-modified", Input: "validate/input/doc-signer-modified.pdf", Offline: true},
		// D. SHA-1 SignerInfo signature algorithm (sha1WithRSAEncryption) with a SHA-256 digest.
		{Name: "weak-sig-alg-sha1-rsa", Input: "validate/input/weak-sig-alg-sha1-rsa.pdf", Offline: true},
		// E. Reader DoS inputs (PDF_INVALID) and the CMS certificate cap (malformed_signature).
		{Name: "xref-stream-w-zero", Input: "validate/input/xref-stream-w-zero.pdf", Offline: true},
		{Name: "xref-stream-zero-rows", Input: "validate/input/xref-stream-zero-rows.pdf", Offline: true},
		{Name: "xref-prev-chain-129", Input: "validate/input/xref-prev-chain-129.pdf", Offline: true},
		{Name: "objstm-many-members", Input: "validate/input/objstm-many-members.pdf", Offline: true},
		{Name: "cms-33-certs", Input: "validate/input/cms-33-certs.pdf", Offline: true},
	}
}

func hardeningVInputs(t *testing.T, p *goldenPKI) map[string][]byte {
	t.Helper()
	base, err := os.ReadFile(filepath.Join(goldenDir, "output", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.ReadFile(filepath.Join(goldenDir, "input", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	qc := vQualifiedCert(t, p)
	qcName := core.SignerDisplayName(qc.cert)
	ds := vDocSigner(t, p)
	attested := vSignWith(t, p, input, ds, "GOLDEN TESTOV", vSigOpts{})
	// signer + 04, 03, 02 + 29 жижиг (P-256, өөрөө зурсан) гэрчилгээ = 33 > maxCMSCerts (placeholder-т багтана).
	chain33 := p.chain()
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 29 {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(3000 + i)), Subject: pkix.Name{CommonName: "TEST ONLY filler"},
			NotBefore: p.citizen.cert.NotBefore, NotAfter: p.citizen.cert.NotAfter}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ek.PublicKey, ek)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		chain33 = append(chain33, c)
	}
	return map[string][]byte{
		"shadow-stream-dss":          vShadow(t, p, false),
		"shadow-control":             vShadow(t, p, true),
		"later-sig-integrity-failed": vSignWith(t, p, base, p.citizen, core.SignerDisplayName(p.citizen.cert), vSigOpts{visible: true, corrupt: true}),
		"later-stamp-name-mismatch":  vSignWith(t, p, base, qc, "GOLDEN TESTOV", vSigOpts{visible: true}),
		"later-stamp-name-control":   vSignWith(t, p, base, qc, qcName, vSigOpts{visible: true}),
		"doc-signer-attested":        attested,
		"doc-signer-modified":        vAppendInfo(t, attested),
		"weak-sig-alg-sha1-rsa":      vWeakSigAlg(t, base),
		"xref-stream-w-zero":         vXrefStreamPDF([]int{0, 0, 0}, "/Index [0 1000000000]", nil),
		"xref-stream-zero-rows":      vXrefStreamPDF([]int{1, 0, 0}, "/Index [0 67108864]", make([]byte, 64<<20)),
		"xref-prev-chain-129":        vPrevChainPDF(129),
		"objstm-many-members":        vManyMembersPDF(200000),
		"cms-33-certs":               vSignWith(t, p, input, p.citizen, core.SignerDisplayName(p.citizen.cert), vSigOpts{chain: chain33}),
	}
}

type vSigOpts struct {
	visible bool                // 1-р хуудсанд 340, 36, 220 × 64 pt иргэний дардас (vStampRev-тэй ижил байрлал)
	corrupt bool                // RSA гарын үсгийн нэг байтыг эргүүлнэ (integrity_failed)
	chain   []*x509.Certificate // CMS-ийн гинж (nil — 04, 03, 02)
}

// vSignWith — base-ийн ард signer-ийн B-B гарын үсэг (timestamp, DSS-гүй), /Name = name; visible бол дардасны нэр мөн name.
func vSignWith(t *testing.T, p *goldenPKI, base []byte, signer *gCert, name string, o vSigOpts) []byte {
	t.Helper()
	at := goldenTime.In(signingZone)
	var prep *core.Prepared
	var err error
	if o.visible {
		docID := docIDFromPage(base)
		vis := core.Visible{Page: 1, X: 34000, Y: 3600, W: 22000, H: 6400, Name: name, Lang: "mn",
			Date: at.Format("2006-01-02 15:04") + " (+08)", URL: pageVerifyURL + docID + "/2"}
		prep, err = core.PrepareSignatureVisible(base, at, name, "", vis)
	} else {
		prep, err = core.PrepareSignature(base, at, name)
	}
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := core.SignedAttributes(prep.Digest, signer.cert)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(nil, signer.key, crypto.SHA256, core.DTBS(attrs))
	if err != nil {
		t.Fatal(err)
	}
	if o.corrupt {
		sig[len(sig)/2] ^= 0x01
	}
	chain := o.chain
	if chain == nil {
		chain = p.chain()
	}
	cms, err := core.AssembleCMS(attrs, signer.cert, chain, sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := core.EmbedCMS(prep.PDF, prep.ByteRange, cms)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// vDocSigner — CA-ийн хуучин stamp-ийн doc-signer (EKU documentSigning 1.3.6.1.5.5.7.3.36, тестийн 04-өөс). validate/pki/-д
// хадгална (дахин -update-д хэвээр).
func vDocSigner(t *testing.T, p *goldenPKI) *gCert {
	t.Helper()
	dir := filepath.Join(validateDir, "pki")
	certPath, keyPath := filepath.Join(dir, "doc-signer.pem"), filepath.Join(dir, "doc-signer.key.pem")
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
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2002), NotBefore: p.citizen.cert.NotBefore, NotAfter: p.citizen.cert.NotAfter,
		Subject:            pkix.Name{CommonName: "TEST ONLY Golden Platform Signer", Country: []string{"MN"}},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 36}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca04.cert, &key.PublicKey, p.ca04.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)                                 // #nosec G306 -- тест
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o644) // #nosec G306 -- ТЕСТИЙН түлхүүр
	return &gCert{cert: c, key: key}
}

// vShadow — golden/input/quartz-pdf13.pdf + R0 (1-р хуудасны /Contents [3 0 R 19 0 R], объект 19 = content stream) +
// иргэний B-B гарын үсэг + DSS-only revision (golden quartz-pdf13-ийн DSS + нэг /Certs stream). complete=false: объект
// 19-ийн /Length гарын үсгийн revision-оос цааш, DSS revision-ий /Certs stream-ийн өгөгдөл дотор «endstream endobj» хүртэл
// үргэлжилнэ — /Length-ийг дагадаг viewer-т 19 нь гарын үсгийн дараах байтыг агуулна. complete=true: 19 нь R0 дотор
// бүтэн (хяналт).
func vShadow(t *testing.T, p *goldenPKI, complete bool) []byte {
	t.Helper()
	in, err := os.ReadFile(filepath.Join(goldenDir, "input", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	gold, err := os.ReadFile(filepath.Join(goldenDir, "output", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	raws, err := validate.Extract(gold)
	if err != nil || len(raws) != 1 || raws[0].DSS == nil {
		t.Fatalf("golden DSS: %v", err)
	}
	id := regexp.MustCompile(`/ID \[[^\]]*\]`).Find(in[bytes.LastIndex(in, []byte("trailer")):])
	prev := bytes.LastIndex(in, []byte("startxref"))
	var prevOff int
	if _, err := fmt.Sscan(string(in[prev+len("startxref"):]), &prevOff); err != nil || id == nil {
		t.Fatal("input trailer", err)
	}
	const tail = "SHADOW\nendstream\nendobj\n"
	build := func(length int) ([]byte, int) {
		var b bytes.Buffer
		b.Write(in)
		off1 := b.Len()
		b.WriteString("1 0 obj\n<< /Type /Page /Parent 2 0 R /Resources 4 0 R /Contents [3 0 R 19 0 R] /MediaBox [0 0 612 792] >>\nendobj\n")
		off19 := b.Len()
		fmt.Fprintf(&b, "19 0 obj\n<< /Length %010d >>\nstream\n", length)
		data := b.Len()
		b.WriteString("q Q")
		if complete {
			b.WriteString("\nendstream\nendobj\n")
		} else {
			b.WriteString("\n")
		}
		xref := b.Len()
		fmt.Fprintf(&b, "xref\n0 2\n0000000000 65535 f \n%010d 00000 n \n19 1\n%010d 00000 n \ntrailer\n<< /Size 20 /Root 11 0 R /Info 12 0 R %s /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
			off1, off19, id, prevOff, xref)
		pre := b.Bytes()
		signed := vSignWith(t, p, pre, p.citizen, core.SignerDisplayName(p.citizen.cert), vSigOpts{})
		sigs, _, _, err := scanSignatures(signed)
		if err != nil || len(sigs) != 1 {
			t.Fatalf("shadow ByteRange: %v", err)
		}
		contents, err := core.SignatureContents(signed, [4]int64(sigs[0].byteRange))
		if err != nil {
			t.Fatal(err)
		}
		d := core.DSS{Certs: append(append([][]byte{}, raws[0].DSS.Certs...), []byte(tail)), OCSPs: raws[0].DSS.OCSPs,
			CRLs: raws[0].DSS.CRLs, Contents: contents}
		out, err := core.AppendDSS(signed, d)
		if err != nil {
			t.Fatal(err)
		}
		at := bytes.LastIndex(out, []byte(tail))
		if at < len(signed) {
			t.Fatal("shadow: DSS tail алга")
		}
		return out, at + len("SHADOW") - data
	}
	if complete {
		out, _ := build(3)
		return out
	}
	_, length := build(0)
	out, again := build(length)
	if again != length {
		t.Fatalf("shadow: layout өөрчлөгдсөн %d ≠ %d", again, length)
	}
	return out
}

// vWeakSigAlg — golden quartz-pdf13-ийн гарын үсгийн SignerInfo.signatureAlgorithm-ийг sha256WithRSAEncryption →
// sha1WithRSAEncryption (OID-ийн сүүлийн байт 0x0B → 0x05) болгоно. /Contents нь ByteRange-ийн гадна тул integrity хэвээр
// (digitorus ба TS RSA-д digest-ээр — SHA-256-аар шалгана).
func vWeakSigAlg(t *testing.T, base []byte) []byte {
	t.Helper()
	sigs, _, _, err := scanSignatures(base)
	if err != nil || len(sigs) != 1 {
		t.Fatalf("ByteRange: %v", err)
	}
	br := sigs[0].byteRange
	contents, err := core.SignatureContents(base, [4]int64(br))
	if err != nil {
		t.Fatal(err)
	}
	// SignerInfo: ... AlgorithmIdentifier{sha256WithRSAEncryption, NULL} OCTET STRING(signature) — гэрчилгээнд BIT STRING.
	pat := []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x04}
	i := bytes.Index(contents, pat)
	if i < 0 {
		t.Fatal("SignerInfo signatureAlgorithm алга")
	}
	out := bytes.Clone(base)
	pos := int(br[1]) + 1 + 2*(i+12) // '<' + hex: OID-ийн сүүлийн байт
	if !strings.EqualFold(string(out[pos:pos+2]), "0b") {
		t.Fatalf("hex %q", out[pos:pos+2])
	}
	copy(out[pos:pos+2], "05")
	return out
}

func vDeflate(b []byte) []byte {
	var z bytes.Buffer
	w, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	return z.Bytes()
}

// vXrefStreamPDF — гарын үсэггүй жижиг PDF: Catalog + xref stream (/W w, extra, өгөгдөл = data-г FlateDecode).
func vXrefStreamPDF(w []int, extra string, data []byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	b.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	x := b.Len()
	z := vDeflate(data)
	fmt.Fprintf(&b, "2 0 obj\n<< /Type /XRef /Size 3 /Root 1 0 R /W [%d %d %d] %s /Filter /FlateDecode /Length %d >>\nstream\n", w[0], w[1], w[2], extra, len(z))
	b.Write(z)
	fmt.Fprintf(&b, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", x)
	return b.Bytes()
}

// vPrevChainPDF — n classic xref хэсэгтэй /Prev гинж (гарын үсэггүй).
func vPrevChainPDF(n int) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	o1 := b.Len()
	b.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	prev := -1
	for range n {
		x := b.Len()
		fmt.Fprintf(&b, "xref\n0 2\n0000000000 65535 f \n%010d 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R", o1)
		if prev >= 0 {
			fmt.Fprintf(&b, " /Prev %d", prev)
		}
		b.WriteString(" >>\n")
		prev = x
	}
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", prev)
	return b.Bytes()
}

// vManyMembersPDF — n гишүүнтэй нэг FlateDecode ObjStm (объект 2…n+1 = «0») + бүгдийг заасан xref stream (гарын үсэггүй).
// Индексгүй уншигч гишүүн бүрд stream-ийг дахин задалж толгойг эхнээс нь уншина: n × len(өгөгдөл).
func vManyMembersPDF(n int) []byte {
	var hdr, body bytes.Buffer
	for i := range n {
		fmt.Fprintf(&hdr, "%d %d ", i+2, body.Len())
		body.WriteString("0 ")
	}
	data := append(hdr.Bytes(), body.Bytes()...)
	z := vDeflate(data)
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	o1 := b.Len()
	b.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	stm := n + 2
	ost := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n<< /Type /ObjStm /N %d /First %d /Filter /FlateDecode /Length %d >>\nstream\n", stm, n, hdr.Len(), len(z))
	b.Write(z)
	b.WriteString("\nendstream\nendobj\n")
	x := b.Len()
	var rows bytes.Buffer
	row := func(typ byte, f2, f3 int) {
		rows.WriteByte(typ)
		rows.Write([]byte{byte(f2 >> 16), byte(f2 >> 8), byte(f2)})
		rows.Write([]byte{byte(f3 >> 16), byte(f3 >> 8), byte(f3)})
	}
	row(0, 0, 0)
	row(1, o1, 0)
	for i := range n {
		row(2, stm, i)
	}
	row(1, ost, 0)
	row(1, x, 0)
	zr := vDeflate(rows.Bytes())
	fmt.Fprintf(&b, "%d 0 obj\n<< /Type /XRef /Size %d /Root 1 0 R /W [1 3 3] /Filter /FlateDecode /Length %d >>\nstream\n", stm+1, stm+2, len(zr))
	b.Write(zr)
	fmt.Fprintf(&b, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", x)
	return b.Bytes()
}

// vWithin — f-ийг d хугацаанд дуусгах ёстой (засварын өмнө эдгээр оролт минут-цаг гацдаг байсан).
func vWithin(t *testing.T, name string, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: %v-д дуусаагүй", name, d)
	}
}

// TestValidatePDFReaderDoS — уншигчийн DoS оролт (E2, E3): урьдчилсан шалгалт PDF_INVALID-ээр хурдан татгалзана; хил
// дээрх хяналт (128 хэсэг, жижиг ObjStm, мөрийн урт > 0) өмнөх шигээ задарна.
func TestValidatePDFReaderDoS(t *testing.T) {
	cases := []struct {
		name string
		doc  []byte
		want string
	}{
		{"w-zero-huge-index", vXrefStreamPDF([]int{0, 0, 0}, "/Index [0 1000000000]", nil), CodePDFInvalid},
		{"w-zero-in-cap", vXrefStreamPDF([]int{0, 0, 0}, "/Index [0 2000000]", nil), CodePDFInvalid},
		{"zero-rows-64MiB", vXrefStreamPDF([]int{1, 0, 0}, "/Index [0 67108864]", make([]byte, 64<<20)), CodePDFInvalid},
		{"index-over-cap", vXrefStreamPDF([]int{1, 0, 0}, "/Index [0 2097153]", make([]byte, 2097153)), CodePDFInvalid},
		{"w-over-8", vXrefStreamPDF([]int{1, 9, 0}, "", nil), CodePDFInvalid},
		{"prev-chain-129", vPrevChainPDF(129), CodePDFInvalid},
		{"prev-chain-128", vPrevChainPDF(128), CodePDFNoSignature},
		{"objstm-200k-members", vManyMembersPDF(200000), CodePDFInvalid},
		{"objstm-100-members", vManyMembersPDF(100), CodePDFNoSignature},
	}
	for _, c := range cases {
		vWithin(t, c.name, 20*time.Second, func() {
			_, err := ValidatePDF(context.Background(), c.doc, ValidateOptions{Offline: true})
			if got := ErrorCode(err); got != c.want {
				t.Errorf("%s: %q (%v), хүлээсэн %q", c.name, got, err, c.want)
			}
		})
	}
}

// TestExtractDSSDedupe — DSS-ийн массив нэг stream-ийг олон удаа заавал нэг удаа уншина (E5); тайлсан нийт байт ≤ 8 MiB.
func TestExtractDSSDedupe(t *testing.T) {
	base, err := os.ReadFile(filepath.Join(goldenDir, "output", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := pdf.NewReader(bytes.NewReader(base), int64(len(base)))
	if err != nil {
		t.Fatal(err)
	}
	tr := r.Trailer()
	root := tr.Key("Root")
	ocsps := root.Key("DSS").Key("OCSPs")
	if ocsps.Len() == 0 {
		t.Fatal("golden DSS: OCSP алга")
	}
	first := vPtrID(ocsps.Index(0))
	want, err := validate.Extract(base)
	if err != nil {
		t.Fatal(err)
	}
	// Шинэ DSS: /OCSPs = эхний OCSP stream × 64, бусад массив хэвээр (заалтаар).
	var arr strings.Builder
	for range 64 {
		fmt.Fprintf(&arr, "%d 0 R ", first)
	}
	refs := func(key string) string {
		a := root.Key("DSS").Key(key)
		var s strings.Builder
		for i := range a.Len() {
			fmt.Fprintf(&s, "%d 0 R ", vPtrID(a.Index(i)))
		}
		return s.String()
	}
	size := int(tr.Key("Size").Int64())
	prev := bytes.LastIndex(base, []byte("startxref"))
	var prevOff int
	if _, err := fmt.Sscan(string(base[prev+len("startxref"):]), &prevOff); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	b.Write(base)
	dssOff := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n<< /Certs [%s] /OCSPs [%s] /CRLs [%s] >>\nendobj\n", size, refs("Certs"), arr.String(), refs("CRLs"))
	catOff := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n<< /Type /Catalog /Pages %d 0 R /DSS %d 0 R >>\nendobj\n", size+1, vPtrID(root.Key("Pages")), size)
	x := b.Len()
	fmt.Fprintf(&b, "xref\n%d 2\n%010d 00000 n \n%010d 00000 n \ntrailer\n<< /Size %d /Root %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
		size, dssOff, catOff, size+2, size+1, prevOff, x)
	raws, err := validate.Extract(b.Bytes())
	if err != nil || len(raws) != 1 || raws[0].DSS == nil {
		t.Fatalf("extract: %v", err)
	}
	if got := len(raws[0].DSS.OCSPs); got != 1 {
		t.Errorf("OCSPs %d, хүлээсэн 1 (давхар заалт)", got)
	}
	if len(raws[0].DSS.Certs) != len(want[0].DSS.Certs) || len(raws[0].DSS.CRLs) != len(want[0].DSS.CRLs) {
		t.Errorf("Certs/CRLs өөрчлөгдсөн")
	}
}

func vPtrID(v pdf.Value) uint32 {
	p := v.GetPtr()
	return p.GetID()
}

// TestValidatePDFLaterStampNameNotCompared — corpus v15: own-signer дардасны /Name-ийг гэрчилгээний нэртэй харьцуулахгүй.
// Бүрэн бүтэн хожмын гарын үсгийн /Name (латин өөр нэр, eID desktop-ийн бичдэг кирилл порталын нэр) гэрчилгээнийхээс
// зөрсөн ч өмнөх гарын үсэг valid, extended_by_signatures_only, visible_later_signature хэвээр; signer_name гэрчилгээнээс.
func TestValidatePDFLaterStampNameNotCompared(t *testing.T) {
	p := loadOrCreatePKI(t)
	base, err := os.ReadFile(filepath.Join(goldenDir, "output", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	qc := vQualifiedCert(t, p)
	qcName := core.SignerDisplayName(qc.cert)
	o := ValidateOptions{Offline: true, Time: goldenNow.UTC(), Roots: vPEMs(t, []string{"golden/pki/root.pem"}),
		Issuers: vPEMs(t, []string{"golden/pki/04.pem", "validate/pki/05.pem"})}
	for _, name := range []string{"GOLDEN TESTOV", "Тестов Голден"} {
		rep, err := ValidatePDF(context.Background(), vSignWith(t, p, base, qc, name, vSigOpts{visible: true}), o)
		if err != nil || len(rep.Signatures) != 2 {
			t.Fatalf("%s: %v", name, err)
		}
		first, later := rep.Signatures[0], rep.Signatures[1]
		if first.CoversWholeDocument {
			first, later = later, first
		}
		if first.Indication != validate.Valid || len(first.Problems) != 0 || !first.ExtendedBySignaturesOnly ||
			!first.VisibleLaterSignature || first.LaterSignatures != 1 {
			t.Errorf("%s: эхний гарын үсэг %s %v ext=%v visible=%v later=%d", name, first.Indication, first.Problems,
				first.ExtendedBySignaturesOnly, first.VisibleLaterSignature, first.LaterSignatures)
		}
		if later.SignerName != qcName || later.ClaimedName != name || !later.Visible {
			t.Errorf("%s: хожмын гарын үсэг signer_name=%q claimed=%q visible=%v", name, later.SignerName, later.ClaimedName, later.Visible)
		}
	}
}
