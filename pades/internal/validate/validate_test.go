package validate

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	eidcrypto "github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/eidcrypto"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/sign"
	"github.com/digitorus/timestamp"
	"github.com/go-pdf/fpdf"
)

// ── Туршилтын PKI: root → issuing → leaf (prod-ийн 01 → … → 04 → doc-signer-тэй ижил хэлбэр) ──

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serialSeq int64 = 100

func issue(t *testing.T, parent *testCA, tmpl *x509.Certificate) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialSeq++
	tmpl.SerialNumber = big.NewInt(serialSeq)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-24 * time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: key}
}

func caTmpl(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

type pki struct {
	root, issuing, leaf, tsa *testCA
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	root := issue(t, nil, caTmpl("Test National Root CA"))
	issuing := issue(t, root, caTmpl("Test eID Issuing CA"))
	leaf := issue(t, issuing, &x509.Certificate{
		Subject:            pkix.Name{CommonName: "eID Mongolia Document Signer"},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidEKUDocumentSigning},
	})
	tsa := issue(t, issuing, &x509.Certificate{
		Subject:         pkix.Name{CommonName: "Test TSA"},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{eidcrypto.TSAEKUExtension()},
	})
	return &pki{root: root, issuing: issuing, leaf: leaf, tsa: tsa}
}

type fakeStatus struct {
	st  CertStatus
	err error
}

func (f fakeStatus) CertStatus(_, _ *x509.Certificate, _ time.Time) (CertStatus, error) {
	return f.st, f.err
}

func (p *pki) validator(st StatusSource) *Validator {
	roots := x509.NewCertPool()
	roots.AddCert(p.root.cert)
	return &Validator{Roots: roots, Intermediates: []*x509.Certificate{p.issuing.cert}, Issuers: []*x509.Certificate{p.issuing.cert}, Status: st}
}

var good = fakeStatus{st: CertStatus{Issued: true}}

func minimalPDF(t *testing.T) []byte {
	t.Helper()
	op := fpdf.New("P", "mm", "A4", "")
	op.SetCompression(false)
	op.AddPage()
	op.SetFont("Helvetica", "", 12)
	op.Cell(40, 10, "Validate test content")
	var b bytes.Buffer
	if err := op.Output(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// tsaServer — RFC 3161 хариулдаг туршилтын TSA.
func tsaServer(t *testing.T, tsa *testCA, parents ...*x509.Certificate) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ts := &timestamp.Timestamp{
			HashAlgorithm:     req.HashAlgorithm,
			HashedMessage:     req.HashedMessage,
			Time:              time.Now().UTC().Truncate(time.Second),
			Policy:            asn1.ObjectIdentifier{1, 2, 3, 4},
			Nonce:             req.Nonce,
			AddTSACertificate: true,
			Certificates:      parents,
		}
		resp, err := ts.CreateResponse(tsa.cert, tsa.key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func signPDF(t *testing.T, doc []byte, signer *testCA, chain []*x509.Certificate, tsaURL string) []byte {
	t.Helper()
	rs := bytes.NewReader(doc)
	rdr, err := pdf.NewReader(rs, int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = sign.Sign(rs, &out, rdr, int64(len(doc)), sign.SignData{
		Signer:            signer.key,
		DigestAlgorithm:   crypto.SHA256,
		Certificate:       signer.cert,
		CertificateChains: [][]*x509.Certificate{append([]*x509.Certificate{signer.cert}, chain...)},
		TSA:               sign.TSA{URL: tsaURL},
		Signature: sign.SignDataSignature{
			CertType: sign.ApprovalSignature,
			Info:     sign.SignDataSignatureInfo{Name: "Бат Болд", Location: "Mongolia", Reason: "eID", Date: time.Now()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func only(t *testing.T, rep *PDFReport) SignatureReport {
	t.Helper()
	if len(rep.Signatures) != 1 {
		t.Fatalf("гарын үсэг %d, хүлээсэн 1", len(rep.Signatures))
	}
	return rep.Signatures[0]
}

// ── PDF ──

func TestValidatePDFValid(t *testing.T) {
	p := newPKI(t)
	signed := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, tsaServer(t, p.tsa, p.issuing.cert))
	rep, err := p.validator(good).ValidatePDF(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	s := only(t, rep)
	if rep.Indication != Valid || s.Indication != Valid || len(s.Problems) != 0 {
		t.Fatalf("хүлээсэн valid, авсан %s %v", s.Indication, s.Problems)
	}
	if s.SignerName != "Бат Болд" || !s.CoversWholeDocument || !s.ChainTrusted {
		t.Fatalf("талбар буруу: %+v", s)
	}
	if s.Timestamp == nil || !s.Timestamp.Trusted || s.SigningTime == nil || s.Timestamp.TSA != "Test TSA" {
		t.Fatalf("цагийн тэмдэг: %+v", s.Timestamp)
	}
	c := s.Certificate
	if c.Usage != "document_signer" || !c.IssuedByEID || c.Revocation.Status != "good" {
		t.Fatalf("гэрчилгээ: %+v", c)
	}
	if want := []string{"eID Mongolia Document Signer", "Test eID Issuing CA", "Test National Root CA"}; !slices.Equal(s.Chain, want) {
		t.Fatalf("гинж %v", s.Chain)
	}
}

// Гинж PDF-д дутуу суулгагдсан ч манай завсрын CA-аас бүтнэ.
func TestValidatePDFChainFromIntermediates(t *testing.T) {
	p := newPKI(t)
	signed := signPDF(t, minimalPDF(t), p.leaf, nil, "")
	v := p.validator(good)
	v.Intermediates = nil
	if s := only(t, mustPDF(t, v, signed)); s.ChainTrusted {
		t.Fatal("завсрын CA-гүйгээр итгэмжлэгдсэн гэж гарлаа")
	}
	v.Intermediates = []*x509.Certificate{p.issuing.cert}
	if s := only(t, mustPDF(t, v, signed)); !s.ChainTrusted || s.Indication != Valid {
		t.Fatalf("хүлээсэн valid, авсан %s %v", s.Indication, s.Problems)
	}
}

func mustPDF(t *testing.T, v *Validator, doc []byte) *PDFReport {
	t.Helper()
	rep, err := v.ValidatePDF(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestValidatePDFTampered(t *testing.T) {
	p := newPKI(t)
	signed := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, "")
	i := bytes.Index(signed, []byte("Validate test content"))
	if i < 0 {
		t.Fatal("агуулга олдсонгүй")
	}
	tampered := bytes.Clone(signed)
	tampered[i] = 'X'
	s := only(t, mustPDF(t, p.validator(good), tampered))
	if s.Indication != Invalid || !slices.Contains(s.Problems, ProblemIntegrity) {
		t.Fatalf("хүлээсэн integrity_failed, авсан %s %v", s.Indication, s.Problems)
	}
}

func TestValidatePDFAppendedAfterSigning(t *testing.T) {
	p := newPKI(t)
	signed := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, "")
	appended := append(bytes.Clone(signed), []byte("\n% нэмэлт засвар\n")...)
	s := only(t, mustPDF(t, p.validator(good), appended))
	if s.CoversWholeDocument || s.Indication != Indeterminate || !slices.Contains(s.Problems, ProblemModifiedAfter) {
		t.Fatalf("хүлээсэн modified_after_signing, авсан %s %v", s.Indication, s.Problems)
	}
}

func TestValidatePDFForeignRoot(t *testing.T) {
	p, other := newPKI(t), newPKI(t)
	signed := signPDF(t, minimalPDF(t), other.leaf, []*x509.Certificate{other.issuing.cert, other.root.cert}, "")
	s := only(t, mustPDF(t, p.validator(good), signed))
	if s.Indication != Invalid || s.ChainTrusted || !slices.Contains(s.Problems, ProblemUntrusted) {
		t.Fatalf("хүлээсэн untrusted, авсан %s %v", s.Indication, s.Problems)
	}
	if s.Certificate.IssuedByEID || s.Certificate.Revocation.Status != "unknown" {
		t.Fatalf("гадны гэрчилгээ: %+v", s.Certificate)
	}
}

func TestValidatePDFRevocation(t *testing.T) {
	p := newPKI(t)
	withTSA := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, tsaServer(t, p.tsa, p.issuing.cert))
	noTSA := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, "")
	before := fakeStatus{st: CertStatus{Issued: true, Revoked: true, RevokedAt: time.Now().Add(-time.Hour)}}
	after := fakeStatus{st: CertStatus{Issued: true, Revoked: true, RevokedAt: time.Now().Add(time.Hour)}}

	cases := map[string]struct {
		doc     []byte
		st      StatusSource
		want    Indication
		problem string
	}{
		"гарын үсгээс өмнө цуцлагдсан":            {withTSA, before, Invalid, ProblemRevoked},
		"цагийн тэмдгийн дараа цуцлагдсан":        {withTSA, after, Valid, ProblemRevokedAfter},
		"цагийн тэмдэггүй — цуцлалт хүчинтэй":     {noTSA, after, Invalid, ProblemRevoked},
		"DB алдаа — good гэж таамаглахгүй":        {withTSA, fakeStatus{err: errors.New("db")}, Indeterminate, ProblemRevocationUnknown},
		"манай бүртгэлд байхгүй serial — unknown": {withTSA, fakeStatus{}, Indeterminate, ProblemRevocationUnknown},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := only(t, mustPDF(t, p.validator(tc.st), tc.doc))
			if s.Indication != tc.want || !slices.Contains(s.Problems, tc.problem) {
				t.Fatalf("хүлээсэн %s/%s, авсан %s %v", tc.want, tc.problem, s.Indication, s.Problems)
			}
		})
	}
}

func TestValidatePDFUntrustedTSA(t *testing.T) {
	p, other := newPKI(t), newPKI(t)
	signed := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, tsaServer(t, other.tsa, other.issuing.cert))
	s := only(t, mustPDF(t, p.validator(good), signed))
	if s.SigningTime != nil || s.Timestamp == nil || s.Timestamp.Trusted {
		t.Fatalf("итгэмжлэгдээгүй TSA-г хүлээн авлаа: %+v", s.Timestamp)
	}
	if s.Indication != Indeterminate || !slices.Contains(s.Problems, ProblemTimestampInvalid) {
		t.Fatalf("хүлээсэн timestamp_invalid, авсан %s %v", s.Indication, s.Problems)
	}
}

func TestValidatePDFRejectsNonPDFAndUnsigned(t *testing.T) {
	v := newPKI(t).validator(good)
	if _, err := v.ValidatePDF(context.Background(), []byte("энэ PDF биш")); !errors.Is(err, ErrNotPDF) {
		t.Fatalf("PDF биш: %v", err)
	}
	if _, err := v.ValidatePDF(context.Background(), minimalPDF(t)); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("гарын үсэггүй: %v", err)
	}
}

// ByteRange-ийн завсар нь ЗӨВХӨН энэ гарын үсгийн /Contents-ийн hex байх ёстой.
func TestSignedBytesGapMustBeTheContents(t *testing.T) {
	doc := []byte("AAAA<0a1B>BBBB")
	contents := []byte{0x0a, 0x1b}
	if signed, whole, ok := signedBytes(doc, []int64{0, 4, 10, 4}, contents); !ok || !whole || string(signed) != "AAAABBBB" {
		t.Fatalf("зөв ByteRange: ok=%v whole=%v signed=%q", ok, whole, signed)
	}
	cases := map[string]struct {
		doc      []byte
		br       []int64
		contents []byte
	}{
		"hex бус завсар":                    {[]byte("AAAA<0a/X>BBBB"), []int64{0, 4, 10, 4}, contents},
		"завсар өөр hex (жишээ нь <..> Tj)": {doc, []int64{0, 4, 10, 4}, []byte{0xff, 0xff}},
		"файлаас хэтэрсэн":                  {doc, []int64{0, 4, 10, 9}, contents},
		"эхлэл 0 биш":                       {doc, []int64{1, 3, 10, 4}, contents},
		"дутуу элемент":                     {doc, []int64{0, 4, 10}, contents},
		"завсар < > -ээр хүрээгүй":          {[]byte("AAAAx0a1BxBBBB"), []int64{0, 4, 10, 4}, contents},
		"int64 халилт":                      {doc, []int64{0, 4, 10, 1<<63 - 1}, contents},
	}
	for name, tc := range cases {
		if _, _, ok := signedBytes(tc.doc, tc.br, tc.contents); ok {
			t.Errorf("%s: хүлээн авлаа", name)
		}
	}
}

// Нэвтрэлтийн (PIN1, clientAuth) гэрчилгээгээр зурсан гарын үсэг — гинж зөв ч хүчингүй.
func TestValidatePDFRejectsNonSigningCertificate(t *testing.T) {
	p := newPKI(t)
	auth := issue(t, p.issuing, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Citizen AUTH"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	s := only(t, mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), auth, []*x509.Certificate{p.issuing.cert}, "")))
	if s.Indication != Invalid || !slices.Contains(s.Problems, ProblemKeyUsage) {
		t.Fatalf("хүлээсэн wrong_key_usage, авсан %s %v", s.Indication, s.Problems)
	}
}

// Үндэсний root-ийн дор гарсан, гэхдээ манай бус CA-ийн гэрчилгээ — цуцлалтыг мэдэхгүй тул valid биш.
func TestValidatePDFOtherSubCAIsIndeterminate(t *testing.T) {
	p := newPKI(t)
	otherCA := issue(t, p.root, caTmpl("Other Provider CA"))
	signer := issue(t, otherCA, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Other signer"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	})
	s := only(t, mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), signer, []*x509.Certificate{otherCA.cert}, "")))
	if !s.ChainTrusted || s.Certificate.IssuedByEID || s.Indication != Indeterminate || !slices.Contains(s.Problems, ProblemRevocationUnknown) {
		t.Fatalf("хүлээсэн indeterminate/revocation_unavailable, авсан %s %v trusted=%v", s.Indication, s.Problems, s.ChainTrusted)
	}
}

// Хугацаа нь дууссан TSA-ийн токен — цагийн тэмдгийг хүлээн авахгүй (хамгаалалт нь суларсан хуучин
// TSA түлхүүрээр цуцлалтаас өмнөх огноог хуурамчаар тавих зам). pdfsign өөрөө ийм токен үүсгэхгүй тул
// дүгнэлтийн үе шатыг шууд шалгана.
func TestEvaluateTimestampRejectsTSAOutsideValidity(t *testing.T) {
	p := newPKI(t)
	oldTSA := issue(t, p.issuing, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Old TSA"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{eidcrypto.TSAEKUExtension()},
		NotBefore:       time.Now().Add(-20 * time.Hour), NotAfter: time.Now().Add(-10 * time.Hour),
	})
	v := p.validator(good)
	raw := RawTimestamp{Time: time.Now(), Matches: true, TSACert: oldTSA.cert.Raw, Certs: [][]byte{p.issuing.cert.Raw}}
	if ts, _, ok := v.evaluateTimestamp(raw); ok || ts.Trusted {
		t.Fatal("хугацааны гадна токеныг хүлээн авлаа")
	}
	raw.Time = time.Now().Add(-15 * time.Hour)
	if _, _, ok := v.evaluateTimestamp(raw); !ok {
		t.Fatal("хугацаан доторх токеныг татгалзлаа")
	}
	raw.TSACert = p.leaf.cert.Raw // timeStamping EKU-гүй
	raw.Time = time.Now()
	if _, _, ok := v.evaluateTimestamp(raw); ok {
		t.Fatal("timeStamping EKU-гүй гэрчилгээг TSA гэж хүлээн авлаа")
	}
}

func TestValidatePDFWeakDigest(t *testing.T) {
	p := newPKI(t)
	doc := minimalPDF(t)
	rs := bytes.NewReader(doc)
	rdr, err := pdf.NewReader(rs, int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = sign.Sign(rs, &out, rdr, int64(len(doc)), sign.SignData{
		Signer: p.leaf.key, DigestAlgorithm: crypto.SHA1, Certificate: p.leaf.cert,
		CertificateChains: [][]*x509.Certificate{{p.leaf.cert, p.issuing.cert}},
		Signature:         sign.SignDataSignature{CertType: sign.ApprovalSignature, Info: sign.SignDataSignatureInfo{Name: "x", Date: time.Now()}},
	})
	if err != nil {
		t.Skipf("SHA-1 гарын үсэг үүсгэж чадсангүй: %v", err)
	}
	s := only(t, mustPDF(t, p.validator(good), out.Bytes()))
	if s.Indication != Invalid || !slices.Contains(s.Problems, ProblemWeakAlgorithm) {
		t.Fatalf("хүлээсэн weak_algorithm, авсан %s %v", s.Indication, s.Problems)
	}
}

// ── Гэрчилгээ ──

func TestValidateCertificate(t *testing.T) {
	p := newPKI(t)
	expired := issue(t, p.issuing, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Expired"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
	})
	signCert := issue(t, p.issuing, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Citizen SIGN"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	})
	foreign := newPKI(t).leaf

	cases := map[string]struct {
		c       *x509.Certificate
		st      StatusSource
		want    Indication
		problem string
		usage   string
	}{
		"хүчинтэй SIGN":   {signCert.cert, good, Valid, "", "sign"},
		"хугацаа дууссан": {expired.cert, good, Invalid, ProblemExpired, "sign"},
		"цуцлагдсан":      {signCert.cert, fakeStatus{st: CertStatus{Issued: true, Revoked: true, RevokedAt: time.Now()}}, Invalid, ProblemRevoked, "sign"},
		"гадны CA":        {foreign.cert, good, Invalid, ProblemUntrusted, "document_signer"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rep := p.validator(tc.st).ValidateCertificate(tc.c)
			if rep.Indication != tc.want || (tc.problem != "" && !slices.Contains(rep.Problems, tc.problem)) {
				t.Fatalf("хүлээсэн %s/%s, авсан %s %v", tc.want, tc.problem, rep.Indication, rep.Problems)
			}
			if rep.Certificate.Usage != tc.usage {
				t.Fatalf("usage %q", rep.Certificate.Usage)
			}
		})
	}
}

func TestParseCertificateForms(t *testing.T) {
	c := newPKI(t).leaf.cert
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	b64 := pemBytes[len("-----BEGIN CERTIFICATE-----\n") : len(pemBytes)-len("-----END CERTIFICATE-----\n")]
	for name, in := range map[string][]byte{"PEM": pemBytes, "толгойгүй base64": b64, "түүхий DER": c.Raw} {
		got, err := ParseCertificate(in)
		if err != nil || !got.Equal(c) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := ParseCertificate([]byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")); !errors.Is(err, ErrNotCert) {
		t.Fatalf("гэрчилгээ биш PEM: %v", err)
	}
}

// TestParseCertificateRawDERWhitespaceTail — гарын үсгийн сүүлийн байт нь whitespace (0x20, 0x0a…) байсан DER-ийг
// TrimSpace тайрч задлахгүй болгодог байв (CI-д ~2% санамсаргүй унадаг). Ийм DER-ийг санамсаргүй гарын үсгээр
// хайж олно (магадлал 6/256; 400 оролдлого ≈ 99.99%); олдохгүй бол алгасна.
func TestParseCertificateRawDERWhitespaceTail(t *testing.T) {
	for i := 0; i < 400; i++ {
		c := issue(t, nil, caTmpl("ws-tail")).cert
		last := c.Raw[len(c.Raw)-1]
		if last != ' ' && last != '\n' && last != '\t' && last != '\r' && last != '\v' && last != '\f' {
			continue
		}
		t.Logf("оролдлого %d: сүүлийн байт 0x%02x", i, last)
		got, err := ParseCertificate(c.Raw)
		if err != nil || !got.Equal(c) {
			t.Fatalf("сүүлийн байт 0x%02x-тэй DER: %v", last, err)
		}
		return
	}
	t.Skip("whitespace-төгсгөлтэй DER 400 оролдлогод олдсонгүй")
}

// Шигтгэсэн root нь pki/chain/01-тэй байт-түвшинд ижил байх ёстой (хуулбар хуучрахаас хамгаална).
func TestEmbeddedRootMatchesPKIChain(t *testing.T) {
	want, err := os.ReadFile("../eidcrypto/chain/01-mongolian-national-root-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(nationalRootPEM)) {
		t.Fatal("national-root-ca.pem нь pki/chain/01-ээс зөрсөн")
	}
	if _, err := NationalRoots(); err != nil {
		t.Fatal(err)
	}
}

// Ижил түлхүүр + subject-тэй дахин олгосон 04 (өөр serial/байт) нь манай олгогч хэвээр; өөр түлхүүр биш.
func TestIsIssuerReissuedSameKey(t *testing.T) {
	p := newPKI(t)
	v := p.validator(good)
	re := p.issuing.cert
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9999), RawSubject: re.RawSubject, SubjectKeyId: re.SubjectKeyId,
		NotBefore: re.NotBefore, NotAfter: re.NotAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: re.KeyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.root.cert, re.PublicKey, p.root.key)
	if err != nil {
		t.Fatal(err)
	}
	reissued, _ := x509.ParseCertificate(der)
	if reissued.Equal(re) || !v.isIssuer(reissued) {
		t.Fatal("дахин олгосон 04 (ижил түлхүүр/subject) олгогч гэж танигдсангүй")
	}
	other := issue(t, p.root, caTmpl("Test eID Issuing CA")) // ижил DN, өөр түлхүүр
	if v.isIssuer(other.cert) {
		t.Fatal("өөр түлхүүртэй CA олгогч гэж танигдлаа")
	}
}
