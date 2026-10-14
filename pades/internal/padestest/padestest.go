// Package padestest — PAdES тестийн үндэсний гинжийн дуурайлт (01 root → 02 → 03 → 04 issuing → иргэн/TSA),
// RFC 3161 TSA, OCSP хариу, CRL. ЗӨВХӨН тестээс импортлоно (prod код хэрэглэхгүй).
package padestest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"

	pades "github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	eidcrypto "github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/eidcrypto"
)

// Cert — гэрчилгээ + хувийн түлхүүр.
type Cert struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// PKI — тестийн үндэсний гинж.
type PKI struct {
	Root, CA02, CA03, CA04, TSA *Cert
}

var serial atomic.Int64

func init() { serial.Store(time.Now().UnixNano() % 1_000_000_000) }

// Issue — parent (nil бол self-signed) -оос tmpl-ийг key-ээр олгоно.
func Issue(t testing.TB, parent *Cert, tmpl *x509.Certificate, key crypto.Signer) *Cert {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(serial.Add(1))
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(365*24*time.Hour)
	}
	pc, pk := tmpl, key
	if parent != nil {
		pc, pk = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, key.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Cert{Cert: c, Key: key}
}

// ECKey — P-256 түлхүүр.
func ECKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func caTmpl(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn, Country: []string{"MN"}}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
}

// New — 01 → 02 → 03 → 04 (ECDSA P-256) + 04-өөс TSA (EKU timeStamping critical).
func New(t testing.TB) *PKI {
	t.Helper()
	p := &PKI{}
	p.Root = Issue(t, nil, caTmpl("Test Mongolian National Root CA"), ECKey(t))
	p.CA02 = Issue(t, p.Root, caTmpl("Test Mongolian National Issuing CA"), ECKey(t))
	p.CA03 = Issue(t, p.CA02, caTmpl("Test Gerege Issuing CA"), ECKey(t))
	p.CA04 = Issue(t, p.CA03, caTmpl("Test eID Mongolia Issuing CA"), ECKey(t))
	p.TSA = Issue(t, p.CA04, &x509.Certificate{Subject: pkix.Name{CommonName: "Test eID Mongolia TSA"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{eidcrypto.TSAEKUExtension()}}, ECKey(t))
	return p
}

// Chain — 04, 03, 02 (root-гүй; CAChain()-тэй ижил дараалал).
func (p *PKI) Chain() []*x509.Certificate {
	return []*x509.Certificate{p.CA04.Cert, p.CA03.Cert, p.CA02.Cert}
}

// Citizen — 04-өөс иргэний SIGN (contentCommitment) гэрчилгээ, RSA bits.
func (p *PKI) Citizen(t testing.TB, given, surname, civilID string, bits int) *Cert {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return Issue(t, p.CA04, &x509.Certificate{
		Subject: pkix.Name{CommonName: surname + "," + given, SerialNumber: "PNOMN-" + civilID, Country: []string{"MN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: given},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: surname},
			}},
		KeyUsage: x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature,
	}, key)
}

// CA04PEM — 04-ийн cert ба key PEM (crypto.LoadCertificateAuthority-д).
func (p *PKI) CA04PEM(t testing.TB) (certPEM, keyPEM []byte) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(p.CA04.Key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.CA04.Cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// OCSP — issuer шууд зурсан (delegated биш) `good` хариу, thisUpdate = now, nextUpdate = now + valid.
func OCSP(t testing.TB, cert, issuer *Cert, valid time.Duration) []byte {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	der, err := ocsp.CreateResponse(issuer.Cert, issuer.Cert, ocsp.Response{
		Status: ocsp.Good, SerialNumber: cert.Cert.SerialNumber, ThisUpdate: now, NextUpdate: now.Add(valid),
	}, issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// OCSPHash — OCSP-ийн CertID hash сонгох хувилбар (ParentCA SHA-1/SHA-256 хос).
func OCSPHash(t testing.TB, cert, issuer *Cert, h crypto.Hash, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	der, err := ocsp.CreateResponse(issuer.Cert, issuer.Cert, ocsp.Response{
		Status: ocsp.Good, SerialNumber: cert.Cert.SerialNumber, ThisUpdate: thisUpdate, NextUpdate: nextUpdate,
		IssuerHash: h,
	}, issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// CRL — issuer-ийн CRL (revoked serial-уудтай), thisUpdate/nextUpdate.
func CRL(t testing.TB, issuer *Cert, thisUpdate, nextUpdate time.Time, revoked ...*big.Int) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: thisUpdate.Add(-time.Hour)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(serial.Add(1)), ThisUpdate: thisUpdate, NextUpdate: nextUpdate, RevokedCertificateEntries: entries,
	}, issuer.Cert, issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TSAServer — RFC 3161 TSA (token-д TSA cert + 04/03/02, timeserver-mn-ийн chain.pem-тэй ижил). fail нь
// true бол 503 (TSA унасан).
func (p *PKI) TSAServer(t testing.TB, fail *atomic.Bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail != nil && fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ts := &timestamp.Timestamp{
			HashAlgorithm: req.HashAlgorithm, HashedMessage: req.HashedMessage,
			Time: time.Now().UTC().Truncate(time.Second), Policy: asn1.ObjectIdentifier{2, 16, 496, 1, 101, 1, 2, 8},
			Nonce: req.Nonce, AddTSACertificate: true, Certificates: p.Chain(), Accuracy: time.Second,
		}
		resp, err := ts.CreateResponse(p.TSA.Cert, p.TSA.Key)
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

// Token — tsaURL-ээс signature-ийн SHA-256-д RFC 3161 token (шалгалтгүй — тест).
func Token(t testing.TB, tsaURL string, signature []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(signature)
	reqDER, err := (&timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: sum[:], Certificates: true}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(tsaURL, "application/timestamp-query", bytes.NewReader(reqDER)) // #nosec G107 -- тест
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	ts, err := timestamp.ParseResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	return ts.RawToken
}

// SignOptions — Sign-ийн тохиргоо.
type SignOptions struct {
	TSAURL string // хоосон бол timestamp-гүй (B-B)
	NoDSS  bool
	// DropOCSP — DSS-ээс иргэний OCSP-г хасна (ltv=false сөрөг тест).
	DropOCSP bool
	// Visible — харагдах гарын үсэг (Name = SignerDisplayName); Role — signer-attributes-v2 claimedRole.
	Visible *pades.Visible
	// SigningTime — /M; тэг бол одоо.
	SigningTime time.Time
}

// Sign — doc-д иргэний PAdES гарын үсэг (prod-ийн memory урсгалтай ижил алхмууд: prepare → DTBS-д PKCS#1 v1.5 →
// TSA → CMS → embed → DSS) нэмнэ. DSS = гинж + TSA гинж, OCSP (иргэн, TSA ← 04; 04 ← 03), CRL (03 ← 02, 02 ← 01).
func (p *PKI) Sign(t testing.TB, doc []byte, citizen *Cert, o SignOptions) []byte {
	t.Helper()
	at := o.SigningTime
	if at.IsZero() {
		at = time.Now()
	}
	var prep *pades.Prepared
	var err error
	role := ""
	if o.Visible != nil {
		role = o.Visible.Role
		prep, err = pades.PrepareSignatureVisible(doc, at, pades.SignerDisplayName(citizen.Cert), "", *o.Visible)
	} else {
		prep, err = pades.PrepareSignature(doc, at, pades.SignerDisplayName(citizen.Cert))
	}
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := pades.SignedAttributesWithRole(prep.Digest, citizen.Cert, role)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := citizen.Key.Sign(rand.Reader, pades.DTBS(attrs), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var tst []byte
	if o.TSAURL != "" {
		tst = Token(t, o.TSAURL, sig)
	}
	cms, err := pades.AssembleCMS(attrs, citizen.Cert, p.Chain(), sig, tst)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pades.EmbedCMS(prep.PDF, prep.ByteRange, cms)
	if err != nil {
		t.Fatal(err)
	}
	if o.NoDSS {
		return signed
	}
	contents, err := pades.SignatureContents(signed, prep.ByteRange)
	if err != nil {
		t.Fatal(err)
	}
	d := pades.DSS{Contents: contents,
		Certs: [][]byte{citizen.Cert.Raw, p.CA04.Cert.Raw, p.CA03.Cert.Raw, p.CA02.Cert.Raw, p.TSA.Cert.Raw},
		OCSPs: [][]byte{OCSP(t, p.TSA, p.CA04, 24*time.Hour), OCSP(t, p.CA04, p.CA03, 7*24*time.Hour)},
		CRLs: [][]byte{
			CRL(t, p.CA03, time.Now().Add(-time.Hour), time.Now().Add(7*24*time.Hour)),
			CRL(t, p.CA02, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour)),
			CRL(t, p.Root, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour)),
		}}
	if !o.DropOCSP {
		d.OCSPs = append(d.OCSPs, OCSP(t, citizen, p.CA04, 24*time.Hour))
	}
	out, err := pades.AppendDSS(signed, d)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TrustPool — TSA token-ийн гинжийг anchor-лох pool (тестийн root).
func (p *PKI) TrustPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.Root.Cert)
	return pool
}
