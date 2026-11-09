package pades

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"testing"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// fakeSealer — CA-ийн /seal/* (тамганы гэрчилгээ + DTBS-ийг байгууллагын түлхүүрээр ECDSA DER).
type fakeSealer struct {
	cert    []byte
	key     *ecdsa.PrivateKey
	retCert []byte // хоосон бол cert
	err     error
	hash    eid.HashAlgorithm
	digest  []byte
}

func (f *fakeSealer) Certificate(context.Context, string) (*eid.SealCertificate, error) {
	return &eid.SealCertificate{OrgEtsi: "NTRMN-6235972", Certificate: f.cert, CertificateLevel: eid.LevelQualified}, nil
}

func (f *fakeSealer) Seal(_ context.Context, org string, digest []byte, h eid.HashAlgorithm) (*eid.SealResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.hash, f.digest = h, digest
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest)
	if err != nil {
		return nil, err
	}
	c := f.retCert
	if c == nil {
		c = f.cert
	}
	return &eid.SealResult{OrgEtsi: org, Signature: sig, Certificate: c}, nil
}

// sealLeaf — CA-ийн ORG_SEAL профайл: KeyUsage = зөвхөн nonRepudiation, EKU-гүй, organizationIdentifier NTRMN-….
func sealLeaf(t *testing.T, p *goldenPKI, ku x509.KeyUsage, serial int64) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Gerege Systems LLC", Organization: []string{"Gerege Systems LLC"},
		Country: []string{"MN"}, ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: "NTRMN-6235972"}}},
		NotBefore: p.citizen.cert.NotBefore, NotAfter: p.citizen.cert.NotAfter, KeyUsage: ku,
		OCSPServer: p.citizen.cert.OCSPServer, CRLDistributionPoints: p.citizen.cert.CRLDistributionPoints}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca04.cert, &key.PublicKey, p.ca04.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return key, leaf
}

func sealOpts(p *goldenPKI, leaf *x509.Certificate) SealOptions {
	p2 := *p
	p2.citizen = &gCert{cert: leaf} // liveResponder нь мэдэгдэх serial-д л OCSP хариулна
	return SealOptions{Reason: "Байгууллагын тамга", SigningTime: goldenTime, Chain: [][]byte{p.ca04.cert.Raw, p.ca03.cert.Raw, p.ca02.cert.Raw},
		Complete: completeOpts(&p2)}
}

// TestSealPDF — тамганы гэрчилгээ → Prepare → SHA-256 DTBS тамгалуулах → Complete → PAdES-BASELINE-LT, usage "seal".
func TestSealPDF(t *testing.T) {
	p := loadOrCreatePKI(t)
	key, leaf := sealLeaf(t, p, x509.KeyUsageContentCommitment, 88001)
	s := &fakeSealer{cert: leaf.Raw, key: key}
	res, err := SealPDF(context.Background(), s, "NTRMN-6235972", readInput(t, "quartz-pdf13.pdf"), sealOpts(p, leaf))
	if err != nil {
		t.Fatal(err)
	}
	if s.hash != eid.SHA256 || len(s.digest) != 32 {
		t.Fatalf("seal call: %s %d", s.hash, len(s.digest))
	}
	if res.HasPage || res.RevIndex != 1 || res.ClaimedRole != "" {
		t.Fatalf("%+v", res)
	}
	rep, err := Verify(res.PDF, VerifyOptions{Roots: [][]byte{p.root.cert.Raw}, Issuers: [][]byte{p.ca04.cert.Raw}, Time: goldenNow})
	if err != nil || rep.Indication != Valid || len(rep.Signatures) != 1 {
		b, _ := json.Marshal(rep)
		t.Fatalf("%v %s", err, b)
	}
	sig := rep.Signatures[0]
	if sig.SignatureLevel != "PAdES-BASELINE-LT" || sig.Timestamp == nil || sig.Certificate == nil || sig.Certificate.Usage != "seal" ||
		sig.SignerName != "Gerege Systems LLC" {
		b, _ := json.Marshal(sig)
		t.Fatalf("%s", b)
	}
}

func TestSealPDFRejects(t *testing.T) {
	p := loadOrCreatePKI(t)
	pdf := readInput(t, "quartz-pdf13.pdf")
	key, leaf := sealLeaf(t, p, x509.KeyUsageContentCommitment, 88002)
	var pe *Error

	// Иргэний SIGN профайл (digitalSignature-тэй) — тамга биш.
	skey, sleaf := sealLeaf(t, p, x509.KeyUsageContentCommitment|x509.KeyUsageDigitalSignature, 88003)
	if _, err := SealPDF(context.Background(), &fakeSealer{cert: sleaf.Raw, key: skey}, "NTRMN-6235972", pdf, sealOpts(p, sleaf)); !errors.As(err, &pe) || pe.Code != CodeSignerInvalid {
		t.Fatalf("non-seal cert: %v", err)
	}
	// Өөр түлхүүрийн гарын үсэг → SIGNATURE_INVALID (Complete).
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := SealPDF(context.Background(), &fakeSealer{cert: leaf.Raw, key: other}, "NTRMN-6235972", pdf, sealOpts(p, leaf)); !errors.As(err, &pe) || pe.Code != CodeSignatureInvalid {
		t.Fatalf("wrong key: %v", err)
	}
	// Тамгалах хооронд гэрчилгээ солигдсон.
	_, leaf2 := sealLeaf(t, p, x509.KeyUsageContentCommitment, 88004)
	if _, err := SealPDF(context.Background(), &fakeSealer{cert: leaf.Raw, key: key, retCert: leaf2.Raw}, "NTRMN-6235972", pdf, sealOpts(p, leaf)); !errors.As(err, &pe) || pe.Code != CodeSignerInvalid {
		t.Fatalf("rotated cert: %v", err)
	}
	// RP-API алдаа хэвээр дамжина (429 → Retryable).
	apiErr := &eid.APIError{Status: 429, Code: "RATE_LIMITED"}
	if _, err := SealPDF(context.Background(), &fakeSealer{cert: leaf.Raw, key: key, err: apiErr}, "NTRMN-6235972", pdf, sealOpts(p, leaf)); !errors.Is(err, apiErr) {
		t.Fatalf("api error: %v", err)
	}
	// TSA заавал: TSA хүрэхгүй бол тамгагүй файл буцаахгүй.
	o := sealOpts(p, leaf)
	o.Complete.TSAURL = "http://tsa.unreachable.test/"
	o.Complete.HTTPClient.Transport = failTransport{}
	if _, err := SealPDF(context.Background(), &fakeSealer{cert: leaf.Raw, key: key}, "NTRMN-6235972", pdf, o); !errors.As(err, &pe) || pe.Code != CodeTSAUnavailable {
		t.Fatalf("tsa: %v", err)
	}
	if _, err := SealPDF(context.Background(), nil, "NTRMN-6235972", pdf, SealOptions{}); !errors.As(err, &pe) || pe.Code != CodeRequestInvalid {
		t.Fatalf("nil sealer: %v", err)
	}
}

// failTransport — сүлжээ хүрэхгүй (TSA унасан).
type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unreachable")
}
