package eid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── тестийн PKI (Go-оор үүсгэнэ — репод түлхүүр хадгалахгүй) ──

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  string
}

var serialN int64

func mkCert(t *testing.T, tmpl *x509.Certificate, parent *testCA, pub crypto.PublicKey, priv crypto.Signer) *testCA {
	t.Helper()
	serialN++
	tmpl.SerialNumber = big.NewInt(serialN)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	}
	pc, pk := tmpl, priv
	if parent != nil {
		pc, pk = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, pub, pk)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: priv, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func caTmpl(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func leafTmpl() *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			Country: []string{"MN"}, CommonName: "DORJ,BAT,PNOMN-12345678", SerialNumber: "PNOMN-12345678",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "BAT"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "DORJ"},
			},
		},
		// v0.6.0: зориулалт анхдагчаар шалгагдана, түвшин гэрчилгээнээс — тестийн «бүх зориулалттай» leaf: KU DS+KE+NR,
		// EKU clientAuth+emailProtection, qcStatements QcCompliance (QUALIFIED).
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
		ExtraExtensions: []pkix.Extension{qcStatementsExt(false)},
	}
}

// qcStatementsExt — ETSI EN 319 412-5 QCStatements: QcCompliance [+ QcSSCD] (CA crypto/ca_profile_org.go-ийн бүтэц).
func qcStatementsExt(sscd bool) pkix.Extension {
	type st struct{ ID asn1.ObjectIdentifier }
	sts := []st{{oidQcCompliance}}
	if sscd {
		sts = append(sts, st{oidQcSSCD})
	}
	v, _ := asn1.Marshal(sts)
	return pkix.Extension{Id: oidQcStatementsExt, Value: v}
}

type pki struct {
	root, inter, rsaLeaf, ecLeaf *testCA
}

var (
	pkiOnce sync.Once
	pkiVal  pki
)

func testPKI(t *testing.T) pki {
	pkiOnce.Do(func() {
		rk, _ := rsa.GenerateKey(rand.Reader, 2048)
		ik, _ := rsa.GenerateKey(rand.Reader, 2048)
		lk, _ := rsa.GenerateKey(rand.Reader, 2048)
		ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		root := mkCert(t, caTmpl("Test Root"), nil, &rk.PublicKey, rk)
		inter := mkCert(t, caTmpl("Test Issuing"), root, &ik.PublicKey, ik)
		pkiVal = pki{
			root: root, inter: inter,
			rsaLeaf: mkCert(t, leafTmpl(), inter, &lk.PublicKey, lk),
			ecLeaf:  mkCert(t, leafTmpl(), inter, &ek.PublicKey, ek),
		}
	})
	return pkiVal
}

func trusted(t *testing.T) *Validator {
	p := testPKI(t)
	// Тестийн issuer нь иргэний 04 биш — анхдагч issuer allowlist-ийг (v0.6.0) унтраана.
	v, err := NewValidator(TrustConfig{TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: []string{p.inter.pem}, AllowAnyIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func untrusted(t *testing.T) *Validator {
	v, err := NewValidator(TrustConfig{AllowUntrusted: true})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

const verifier = "dGVzdC12ZXJpZmllci0zMi1ieXRlcy14eHh4eHh4eHg"

func signDigest(t *testing.T, key crypto.Signer, alg string, h crypto.Hash, digest []byte) string {
	t.Helper()
	var sig []byte
	var err error
	switch alg {
	case "rsassa-pss":
		sig, err = rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), h, digest, &rsa.PSSOptions{SaltLength: h.Size()})
	case "ecdsa":
		sig, err = ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), digest)
	default:
		sig, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), h, digest)
	}
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

type authOpts struct {
	callback   string
	signed     *string // payload-д зурагдсан callback; nil = callback
	inResponse *string // хариуны signature.initialCallbackUrl; nil = талбар алга
	leaf       *testCA
	alg        string // хариуны signatureAlgorithm
	hash       HashAlgorithm
}

func sp(s string) *string { return &s }

// signedAuth — бодит ACSP_V2 гарын үсэгтэй COMPLETE/OK хариу + RP-ийн ACSP контекст.
func signedAuth(t *testing.T, flow string, o authOpts) (*SessionResult, *ACSPContext) {
	t.Helper()
	p := testPKI(t)
	if o.leaf == nil {
		o.leaf = p.rsaLeaf
	}
	if o.alg == "" {
		o.alg = "rsassa-pss"
	}
	if o.hash == "" {
		o.hash = SHA256
	}
	ch, _ := RandomChallenge(0)
	flows := []FlowType{FlowQR}
	if o.callback != "" {
		flows = []FlowType{FlowQR, FlowApp2App, FlowWeb2App}
	}
	acsp := &ACSPContext{
		RPChallenge: ch, RelyingPartyName: "DEMO", Interactions: smartIDVector.Interactions,
		InitialCallbackURL: o.callback, FlowTypes: flows, SignatureAlgorithm: AlgRSASSAPSS, HashAlgorithm: o.hash,
	}
	signedCB := o.callback
	if o.signed != nil {
		signedCB = *o.signed
	}
	uc := UserChallengeOf(verifier)
	payload := BuildACSPV2Payload(ACSPV2Params{
		ServerRandom: smartIDVector.ServerRandom, RPChallenge: ch, UserChallenge: uc, RelyingPartyName: "DEMO",
		Interactions: acsp.Interactions, InteractionTypeUsed: "displayTextAndPIN", InitialCallbackURL: signedCB, FlowType: flow,
	})
	hh, _ := cryptoHash(string(o.hash))
	d := hh.New()
	d.Write(payload)
	signAlg := o.alg
	if strings.HasPrefix(o.alg, "ecdsa") {
		signAlg = "ecdsa"
	}
	r := &SessionResult{
		State: StateComplete, EndResult: EndResultOK, DocumentNumber: "PNOMN-TEST", SignatureProtocol: "ACSP_V2",
		InteractionTypeUsed: "displayTextAndPIN", SignatureValueB64: signDigest(t, o.leaf.key, signAlg, hh, d.Sum(nil)),
		ServerRandom: smartIDVector.ServerRandom, UserChallenge: uc, FlowType: flow, InitialCallbackURL: o.inResponse,
		SignatureAlgorithm: o.alg, SignatureAlgorithmParameters: &SignatureAlgorithmParameters{HashAlgorithm: string(o.hash)},
		CertificateDERB64: base64.StdEncoding.EncodeToString(o.leaf.cert.Raw), CertificateLevel: "QUALIFIED",
	}
	return r, acsp
}

func wantInvalid(t *testing.T, err error, contains string) {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("ValidationError хүлээв, авсан %v", err)
	}
	if contains != "" && !strings.Contains(ve.Reason, contains) {
		t.Fatalf("%q агуулаагүй: %q", contains, ve.Reason)
	}
}

// ── гарын үсгийн алгоритмууд ──

func TestVerifySignatures_AllAlgorithms(t *testing.T) {
	p := testPKI(t)
	payload := BuildACSPV2Payload(smartIDVector)
	for _, h := range []struct {
		name HashAlgorithm
		ch   crypto.Hash
	}{{SHA256, crypto.SHA256}, {SHA384, crypto.SHA384}, {SHA512, crypto.SHA512}} {
		d := h.ch.New()
		d.Write(payload)
		digest := d.Sum(nil)
		pss := signDigest(t, p.rsaLeaf.key, "rsassa-pss", h.ch, digest)
		pkcs := signDigest(t, p.rsaLeaf.key, "pkcs1", h.ch, digest)
		ec := signDigest(t, p.ecLeaf.key, "ecdsa", h.ch, digest)
		rsaPub, ecPub := p.rsaLeaf.cert.PublicKey, p.ecLeaf.cert.PublicKey
		pkcsAlg := "sha" + string(h.name)[4:] + "WithRSAEncryption"
		ok := []bool{
			VerifyPayloadSignature(payload, pss, rsaPub, "rsassa-pss", string(h.name)),
			VerifyPrehashedSignature(digest, pss, rsaPub, "rsassa-pss", string(h.name)),
			VerifyPayloadSignature(payload, pkcs, rsaPub, pkcsAlg, string(h.name)),
			VerifyPrehashedSignature(digest, pkcs, rsaPub, pkcsAlg, string(h.name)),
			VerifyPayloadSignature(payload, ec, ecPub, "ecdsa-with-SHA256", string(h.name)) == (h.name == SHA256),
			VerifyPrehashedSignature(digest, ec, ecPub, "ecdsa-with-SHA256", string(h.name)) == (h.name == SHA256),
		}
		for i, v := range ok {
			if !v {
				t.Fatalf("%s #%d verify унав", h.name, i)
			}
		}
		bad := []bool{
			VerifyPayloadSignature([]byte("x"), pss, rsaPub, "rsassa-pss", string(h.name)),
			VerifyPrehashedSignature(digest, pkcs, rsaPub, "rsassa-pss", string(h.name)), // PKCS1 ≠ PSS
			VerifyPrehashedSignature(digest, pss, rsaPub, pkcsAlg, string(h.name)),
			VerifyPrehashedSignature(digest, ec, rsaPub, "ecdsa-with-SHA256", string(h.name)), // alg confusion
			VerifyPrehashedSignature(digest, pss, ecPub, "rsassa-pss", string(h.name)),
			VerifyPrehashedSignature(digest[:20], ec, ecPub, "ecdsa-with-SHA256", string(h.name)),
		}
		for i, v := range bad {
			if v {
				t.Fatalf("%s bad #%d зөвшөөрөгдөв", h.name, i)
			}
		}
	}
}

// ── ValidateAuth: flowType / verifier (device-link relay хаалт) ──

func TestValidateAuth_Flows(t *testing.T) {
	V := untrusted(t)
	cb := "https://rp.test/cb"
	r, a := signedAuth(t, "QR", authOpts{callback: cb})
	who, err := V.ValidateAuth(r, a, ValidateAuthOptions{})
	if err != nil || who.DocumentNumber != "PNOMN-TEST" {
		t.Fatal(err)
	}
	if who.Subject.GivenName != "BAT" || who.Subject.Surname != "DORJ" || who.Subject.SerialNumber != "PNOMN-12345678" || who.Subject.Country != "MN" {
		t.Fatalf("subject %+v", who.Subject)
	}
	if _, err := V.ValidateAuth(r, a, ValidateAuthOptions{ExpectedFlowType: FlowQR}); err != nil {
		t.Fatal(err)
	}
	relay, ra := signedAuth(t, "Web2App", authOpts{callback: cb})
	_, err = V.ValidateAuth(relay, ra, ValidateAuthOptions{ExpectedFlowType: FlowQR})
	wantInvalid(t, err, "эхлүүлсэн урсгал QR")
	if _, err := V.ValidateAuth(relay, ra, ValidateAuthOptions{ExpectedFlowType: FlowWeb2App, UserChallengeVerifier: verifier}); err != nil {
		t.Fatal(err)
	}
	for _, flow := range []string{"Web2App", "App2App"} {
		r, a := signedAuth(t, flow, authOpts{callback: cb})
		_, err := V.ValidateAuth(r, a, ValidateAuthOptions{ExpectedFlowType: FlowType(flow)})
		wantInvalid(t, err, "userChallengeVerifier заавал")
		_, err = V.ValidateAuth(r, a, ValidateAuthOptions{ExpectedFlowType: FlowType(flow), UserChallengeVerifier: verifier + "x"})
		wantInvalid(t, err, "userChallengeVerifier нь")
	}
	for _, flow := range []string{"QR", "App2App"} {
		r, a := signedAuth(t, flow, authOpts{callback: cb})
		_, err := V.ValidateAuth(r, a, ValidateAuthOptions{ExpectedFlowType: FlowWeb2App, UserChallengeVerifier: verifier})
		wantInvalid(t, err, "эхлүүлсэн урсгал Web2App")
	}
	// хариуны flowType-ийг солиход гарын үсэг таарахгүй
	tampered := *relay
	tampered.FlowType = "QR"
	_, err = V.ValidateAuth(&tampered, ra, ValidateAuthOptions{ExpectedFlowType: FlowQR})
	wantInvalid(t, err, "ACSP_V2 payload-той таарсангүй")
	// callback-гүй session-д Web2App санал болгоогүй
	nocb, na := signedAuth(t, "Web2App", authOpts{})
	_, err = V.ValidateAuth(nocb, na, ValidateAuthOptions{})
	wantInvalid(t, err, "санал болгосон урсгалд байхгүй")
}

func TestValidateAuth_MissingFields(t *testing.T) {
	V := untrusted(t)
	r, a := signedAuth(t, "QR", authOpts{})
	for name, f := range map[string]func(*SessionResult){
		"signature":   func(r *SessionResult) { r.SignatureValueB64 = "" },
		"cert":        func(r *SessionResult) { r.CertificateDERB64 = "" },
		"docnum":      func(r *SessionResult) { r.DocumentNumber = "" },
		"state":       func(r *SessionResult) { r.State = StateRunning },
		"protocol":    func(r *SessionResult) { r.SignatureProtocol = "RAW_DIGEST_SIGNATURE" },
		"random":      func(r *SessionResult) { r.ServerRandom = "c2hvcnQ=" },
		"uc":          func(r *SessionResult) { r.UserChallenge = "short" },
		"interaction": func(r *SessionResult) { r.InteractionTypeUsed = "" },
		"level":       func(r *SessionResult) { r.CertificateLevel = "ADVANCED" },
		"alg":         func(r *SessionResult) { r.SignatureAlgorithm = "md5WithRSA" },
		"hash":        func(r *SessionResult) { r.SignatureAlgorithmParameters.HashAlgorithm = "SHA-512" },
		"salt":        func(r *SessionResult) { n := 20; r.SignatureAlgorithmParameters.SaltLength = &n },
	} {
		c := *r
		p := *r.SignatureAlgorithmParameters
		c.SignatureAlgorithmParameters = &p
		f(&c)
		if _, err := V.ValidateAuth(&c, a, ValidateAuthOptions{}); err == nil {
			t.Errorf("%s: зөвшөөрөгдөв", name)
		}
	}
	c := *r
	c.EndResult = EndResultUserRefused
	var sf *SessionFailedError
	if _, err := V.ValidateAuth(&c, a, ValidateAuthOptions{}); !errors.As(err, &sf) || sf.EndResult != "USER_REFUSED" {
		t.Fatal(err)
	}
	// v0.6.0: хариу гэрчилгээнээс (QUALIFIED — QcSSCD алга) өндөр түвшин зарлавал татгалзана.
	c = *r
	c.CertificateLevel = "QSCD"
	_, err := V.ValidateAuth(&c, a, ValidateAuthOptions{})
	wantInvalid(t, err, "гэрчилгээнээс (QUALIFIED) өндөр")
}

// ── ACSP_V2 initialCallbackUrl — CA урсгалаар шийднэ, хариунаас сэргээнэ ──

func TestValidateAuth_InitialCallbackURL(t *testing.T) {
	V := untrusted(t)
	cb := "https://rp.test/cb"
	ok := func(flow string, o authOpts, exp FlowType) {
		t.Helper()
		o.callback = cb
		r, a := signedAuth(t, flow, o)
		if exp == FlowNotification {
			a.FlowTypes = []FlowType{FlowNotification, FlowApp2App, FlowWeb2App}
		}
		vo := ValidateAuthOptions{ExpectedFlowType: exp}
		if exp == FlowWeb2App || exp == FlowApp2App {
			vo.UserChallengeVerifier = verifier
		}
		if _, err := V.ValidateAuth(r, a, vo); err != nil {
			t.Fatalf("%s: %v", flow, err)
		}
	}
	ok("QR", authOpts{signed: sp(""), inResponse: sp("")}, FlowQR)           // v3 QR: зурагдсан ""
	ok("Web2App", authOpts{signed: sp(cb), inResponse: sp(cb)}, FlowWeb2App) // callback
	ok("App2App", authOpts{signed: sp(cb), inResponse: sp(cb)}, FlowApp2App) // callback
	ok("Notification", authOpts{signed: sp(cb), inResponse: sp(cb)}, FlowNotification)
	ok("Notification", authOpts{signed: sp(""), inResponse: sp("")}, FlowNotification)
	ok("QR", authOpts{signed: sp(cb), inResponse: sp(cb)}, FlowQR) // хуучин /dl QR
	ok("QR", authOpts{}, FlowQR)                                   // талбар алга (хуучин CA) → RP-ийн callback

	evil := "https://evil.test/cb"
	r, a := signedAuth(t, "QR", authOpts{callback: cb, signed: sp(evil), inResponse: sp(evil)})
	_, err := V.ValidateAuth(r, a, ValidateAuthOptions{})
	wantInvalid(t, err, "хоосон ч биш, илгээсэн callback ч биш")
	r, a = signedAuth(t, "Web2App", authOpts{callback: cb, inResponse: sp(cb + "?x=1")})
	_, err = V.ValidateAuth(r, a, ValidateAuthOptions{ExpectedFlowType: FlowWeb2App, UserChallengeVerifier: verifier})
	wantInvalid(t, err, "хоосон ч биш")
	r, a = signedAuth(t, "QR", authOpts{signed: sp(cb), inResponse: sp(cb)}) // callback-гүй session
	_, err = V.ValidateAuth(r, a, ValidateAuthOptions{})
	wantInvalid(t, err, "хоосон ч биш")
	for _, flow := range []string{"Web2App", "App2App"} {
		r, a := signedAuth(t, flow, authOpts{callback: cb, signed: sp(""), inResponse: sp("")})
		_, err := V.ValidateAuth(r, a, ValidateAuthOptions{ExpectedFlowType: FlowType(flow), UserChallengeVerifier: verifier})
		wantInvalid(t, err, flow+" урсгалд signature.initialCallbackUrl")
	}
	r, a = signedAuth(t, "QR", authOpts{callback: cb, signed: sp("")}) // хуучин CA + зурагдсан "" — боломжгүй
	_, err = V.ValidateAuth(r, a, ValidateAuthOptions{})
	wantInvalid(t, err, "ACSP_V2 payload-той таарсангүй")
}

// ── ECDSA (токен / HSM / хуучин threshold): hash = хүссэн hash, түлхүүрийн төрөл тулгалт ──

func TestValidateAuth_ECDSA(t *testing.T) {
	V := untrusted(t)
	p := testPKI(t)
	r, a := signedAuth(t, "QR", authOpts{leaf: p.ecLeaf, alg: "ecdsa-with-SHA256", hash: SHA256})
	if _, err := V.ValidateAuth(r, a, ValidateAuthOptions{ExpectedFlowType: FlowQR}); err != nil {
		t.Fatal(err)
	}
	// CA-ийн ECDSA credential зөвхөн SHA-256 — SHA-384/512 session-д ECDSA хариу боломжгүй → татгалзана.
	for _, h := range []HashAlgorithm{SHA384, SHA512} {
		r, a := signedAuth(t, "QR", authOpts{leaf: p.ecLeaf, alg: "ecdsa-with-SHA256", hash: h})
		_, err := V.ValidateAuth(r, a, ValidateAuthOptions{})
		wantInvalid(t, err, "ECDSA credential зөвхөн SHA-256")
	}
	// бусад ECDSA нэр дэмжигдэхгүй
	r, a = signedAuth(t, "QR", authOpts{leaf: p.ecLeaf, alg: "ecdsa-with-SHA256"})
	r.SignatureAlgorithm = "ecdsa-with-SHA512"
	_, err := V.ValidateAuth(r, a, ValidateAuthOptions{})
	wantInvalid(t, err, "дэмжигдээгүй")
	// EC гарын үсгийг RSA гэрчилгээтэй (alg confusion)
	r, a = signedAuth(t, "QR", authOpts{leaf: p.ecLeaf, alg: "ecdsa-with-SHA256"})
	r.CertificateDERB64 = base64.StdEncoding.EncodeToString(p.rsaLeaf.cert.Raw)
	_, err = V.ValidateAuth(r, a, ValidateAuthOptions{})
	wantInvalid(t, err, "EC P-256 бус")
	// P-384 түлхүүр
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	leaf384 := mkCert(t, leafTmpl(), p.inter, &k384.PublicKey, k384)
	r, a = signedAuth(t, "QR", authOpts{leaf: leaf384, alg: "ecdsa-with-SHA256"})
	_, err = V.ValidateAuth(r, a, ValidateAuthOptions{})
	wantInvalid(t, err, "EC P-256 бус")
	// RSA нэр EC гэрчилгээтэй
	r, a = signedAuth(t, "QR", authOpts{leaf: p.ecLeaf, alg: "ecdsa-with-SHA256"})
	r.SignatureAlgorithm = "rsassa-pss"
	_, err = V.ValidateAuth(r, a, ValidateAuthOptions{})
	wantInvalid(t, err, "RSA бус")
}

// ── ValidateSign ──

func TestValidateSign(t *testing.T) {
	V := trusted(t)
	p := testPKI(t)
	doc := []byte("%PDF-1.7 гэрээ")
	d256 := sha256.Sum256(doc)
	d512 := sha512.Sum512(doc)
	mk := func(leaf *testCA, alg, signAlg string, h crypto.Hash, digest []byte) *SessionResult {
		return &SessionResult{
			State: StateComplete, EndResult: EndResultOK, DocumentNumber: "PNOMN-TEST", SignatureProtocol: "RAW_DIGEST_SIGNATURE",
			SignatureAlgorithm: alg, SignatureAlgorithmParameters: &SignatureAlgorithmParameters{HashAlgorithm: map[crypto.Hash]string{crypto.SHA256: "SHA-256", crypto.SHA512: "SHA-512"}[h]},
			SignatureValueB64: signDigest(t, leaf.key, signAlg, h, digest), CertificateLevel: "QUALIFIED",
			CertificateDERB64: base64.StdEncoding.EncodeToString(leaf.cert.Raw),
		}
	}
	b := base64.StdEncoding.EncodeToString
	cases := []struct {
		r      *SessionResult
		digest string
		hash   HashAlgorithm
	}{
		{mk(p.rsaLeaf, "rsassa-pss", "rsassa-pss", crypto.SHA256, d256[:]), b(d256[:]), ""},
		{mk(p.rsaLeaf, "rsassa-pss", "rsassa-pss", crypto.SHA512, d512[:]), b(d512[:]), SHA512},
		{mk(p.rsaLeaf, "sha256WithRSAEncryption", "pkcs1", crypto.SHA256, d256[:]), b(d256[:]), SHA256},
		{mk(p.ecLeaf, "ecdsa-with-SHA256", "ecdsa", crypto.SHA256, d256[:]), b(d256[:]), SHA256},
	}
	for i, c := range cases {
		s, err := V.ValidateSign(c.r, c.digest, c.hash)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		if s.Subject.SerialNumber != "PNOMN-12345678" {
			t.Fatal(s.Subject)
		}
	}
	other := sha256.Sum256([]byte("өөр баримт"))
	_, err := V.ValidateSign(cases[0].r, b(other[:]), "")
	wantInvalid(t, err, "digest-тэй таарсангүй")
	_, err = V.ValidateSign(cases[0].r, b(d512[:]), "")
	wantInvalid(t, err, "")
	_, err = V.ValidateSign(cases[1].r, b(d512[:]), SHA256) // downgrade
	wantInvalid(t, err, "hashAlgorithm")
	ec512 := mk(p.ecLeaf, "ecdsa-with-SHA256", "ecdsa", crypto.SHA512, d512[:])
	_, err = V.ValidateSign(ec512, b(d512[:]), SHA512)
	wantInvalid(t, err, "ECDSA credential зөвхөн SHA-256")
}

func TestValidateSignExpectedFlowType(t *testing.T) {
	V := trusted(t)
	p := testPKI(t)
	d := sha256.Sum256([]byte("%PDF-1.7 гэрээ"))
	digest := base64.StdEncoding.EncodeToString(d[:])
	mk := func(flow string) *SessionResult {
		return &SessionResult{
			State: StateComplete, EndResult: EndResultOK, DocumentNumber: "PNOMN-TEST", SignatureProtocol: "RAW_DIGEST_SIGNATURE",
			SignatureAlgorithm: "ecdsa-with-SHA256", FlowType: flow, CertificateLevel: "QUALIFIED",
			SignatureValueB64: signDigest(t, p.ecLeaf.key, "ecdsa", crypto.SHA256, d[:]),
			CertificateDERB64: base64.StdEncoding.EncodeToString(p.ecLeaf.cert.Raw),
		}
	}
	for _, f := range []FlowType{FlowQR, FlowWeb2App, FlowApp2App, FlowNotification} {
		if _, err := V.ValidateSign(mk(string(f)), digest, SHA256, ValidateSignOptions{ExpectedFlowType: f}); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	_, err := V.ValidateSign(mk("Web2App"), digest, SHA256, ValidateSignOptions{ExpectedFlowType: FlowQR})
	wantInvalid(t, err, "эхлүүлсэн урсгал QR")
	_, err = V.ValidateSign(mk(""), digest, "", ValidateSignOptions{ExpectedFlowType: FlowNotification})
	wantInvalid(t, err, "эхлүүлсэн урсгал Notification")
	_, err = V.ValidateSign(mk("QR"), digest, "", ValidateSignOptions{}, ValidateSignOptions{})
	wantInvalid(t, err, "дээд тал нь нэг")
	// сонголтгүй / хоосон — одоогийн зан (flowType шалгахгүй)
	for _, o := range [][]ValidateSignOptions{nil, {{}}} {
		if _, err := V.ValidateSign(mk("Web2App"), digest, SHA256, o...); err != nil {
			t.Fatal(err)
		}
	}
}

// ── гэрчилгээний гинж ──

func TestChain(t *testing.T) {
	p := testPKI(t)
	r, a := signedAuth(t, "QR", authOpts{})
	if _, err := trusted(t).ValidateAuth(r, a, ValidateAuthOptions{}); err != nil {
		t.Fatal(err)
	}
	// anchor алга → fail-closed
	v0, _ := NewValidator(TrustConfig{})
	_, err := v0.ValidateAuth(r, a, ValidateAuthOptions{})
	wantInvalid(t, err, "trust anchor тохируулаагүй")
	// intermediate алга
	v1, _ := NewValidator(TrustConfig{TrustAnchorsPEM: []string{p.root.pem}})
	_, err = v1.ValidateAuth(r, a, ValidateAuthOptions{})
	wantInvalid(t, err, "гинж")
	// өөр root
	ok, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherRoot := mkCert(t, caTmpl("Test Root"), nil, &ok.PublicKey, ok) // ижил нэр, өөр түлхүүр
	v2, _ := NewValidator(TrustConfig{TrustAnchorsPEM: []string{otherRoot.pem}, IntermediatesPEM: []string{p.inter.pem}})
	_, err = v2.ValidateAuth(r, a, ValidateAuthOptions{})
	wantInvalid(t, err, "гинж")
	// CA биш issuer (leaf-ээр зурсан leaf)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notCA := mkCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Not CA"}, BasicConstraintsValid: true}, p.inter, &ek.PublicKey, ek)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	child := mkCert(t, leafTmpl(), notCA, &lk.PublicKey, lk)
	v3, _ := NewValidator(TrustConfig{TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: []string{p.inter.pem, notCA.pem}})
	r2 := *r
	r2.CertificateDERB64 = base64.StdEncoding.EncodeToString(child.cert.Raw)
	_, err = v3.ValidateAuth(&r2, a, ValidateAuthOptions{})
	wantInvalid(t, err, "") // гинж эсвэл гарын үсэг
	// хугацаа дууссан leaf
	expT := leafTmpl()
	expT.NotBefore, expT.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	xk, _ := rsa.GenerateKey(rand.Reader, 2048)
	expired := mkCert(t, expT, p.inter, &xk.PublicKey, xk)
	r3 := *r
	r3.CertificateDERB64 = base64.StdEncoding.EncodeToString(expired.cert.Raw)
	_, err = trusted(t).ValidateAuth(&r3, a, ValidateAuthOptions{})
	wantInvalid(t, err, "хугацаа дууссан")
	// clock skew дотор зөвшөөрнө (гарын үсэг таарахгүй ч хугацаа ба гинжийн шалгалтыг давна): гинжийг leaf-ийн
	// хүчинтэй хугацаанд хавчсан мөчөөр шалгана.
	jT := leafTmpl()
	jT.NotBefore, jT.NotAfter = time.Now().Add(-50*time.Minute), time.Now().Add(-30*time.Minute)
	justExpired := mkCert(t, jT, p.inter, &xk.PublicKey, xk)
	r4 := *r
	r4.CertificateDERB64 = base64.StdEncoding.EncodeToString(justExpired.cert.Raw)
	_, err = trusted(t).ValidateAuth(&r4, a, ValidateAuthOptions{})
	wantInvalid(t, err, "хугацаа дууссан")
	vs, _ := NewValidator(TrustConfig{TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: []string{p.inter.pem}, ClockSkew: time.Hour, AllowAnyIssuer: true})
	_, err = vs.ValidateAuth(&r4, a, ValidateAuthOptions{})
	wantInvalid(t, err, "ACSP_V2 payload")
	if _, err := NewValidator(TrustConfig{TrustAnchorsPEM: []string{"not pem"}}); err == nil {
		t.Fatal("буруу PEM зөвшөөрөгдөв")
	}
}

// Бодит нийтийн гэрчилгээнүүд (testdata): eID Mongolia Issuing CA (04) ← Gerege Issuing CA (03), ба NationalRootCAPEM.
func TestChain_RealPublicCAs(t *testing.T) {
	read := func(n string) string {
		b, err := os.ReadFile("testdata/" + n)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	certs, err := parseCerts([]string{read("eid-mongolia-issuing-ca.pem"), read("gerege-issuing-ca.pem"), NationalRootCAPEM})
	if err != nil {
		t.Fatal(err)
	}
	ca04, ca03, root := certs[0], certs[1], certs[2]
	if !issuedBy(ca04, ca03) {
		t.Fatal("04 ← 03 гинж задарсангүй")
	}
	if issuedBy(ca03, root) {
		t.Fatal("03-ийг root шууд гаргаагүй (дунд нь MDDC 02)")
	}
	fp := sha256.Sum256(root.Raw)
	if got := strings.ToUpper(hexColon(fp[:])); got != "CB:E7:F3:FE:1F:04:80:37:C2:15:DA:32:1E:58:CA:A4:F3:63:DE:9E:54:BB:C4:42:A3:BF:D6:2F:AD:83:44:82" {
		t.Fatalf("root fingerprint %s", got)
	}
	if root.Subject.CommonName != "Mongolian National Root CA" || !root.IsCA {
		t.Fatal(root.Subject)
	}
}

func hexColon(b []byte) string {
	const hx = "0123456789abcdef"
	var s []string
	for _, c := range b {
		s = append(s, string([]byte{hx[c>>4], hx[c&15]}))
	}
	return strings.Join(s, ":")
}

// ── цуцлалт ──

func TestCheckRevocation(t *testing.T) {
	p := testPKI(t)
	mk := func(st RevocationStatus, err error, mode RevocationMode) *Validator {
		v, _ := NewValidator(TrustConfig{
			TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: []string{p.inter.pem}, RevocationMode: mode,
			Revocation: func(_ context.Context, cert, issuer *x509.Certificate) (RevocationStatus, error) {
				if issuer == nil || issuer.Subject.CommonName != "Test Issuing" {
					t.Errorf("issuer %v", issuer)
				}
				return st, err
			},
		})
		return v
	}
	ctx := context.Background()
	leaf := p.rsaLeaf.cert
	if err := mk(RevocationGood, nil, "").CheckRevocation(ctx, leaf); err != nil {
		t.Fatal(err)
	}
	wantInvalid(t, mk(RevocationRevoked, nil, "").CheckRevocation(ctx, leaf), "цуцлагдсан")
	wantInvalid(t, mk(RevocationUnknown, nil, "").CheckRevocation(ctx, leaf), "hard-fail")
	if err := mk(RevocationUnknown, nil, RevocationSoftFail).CheckRevocation(ctx, leaf); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("ocsp down")
	if err := mk(RevocationGood, boom, RevocationSoftFail).CheckRevocation(ctx, leaf); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if err := trusted(t).CheckRevocation(ctx, leaf); err != nil { // hook алга → no-op
		t.Fatal(err)
	}
}

func TestParseSubject(t *testing.T) {
	s := ParseSubject(testPKI(t).rsaLeaf.cert)
	want := Subject{GivenName: "BAT", Surname: "DORJ", CommonName: "DORJ,BAT,PNOMN-12345678", SerialNumber: "PNOMN-12345678", Country: "MN"}
	if s != want {
		t.Fatalf("%+v", s)
	}
	if ParseSubject(nil) != (Subject{}) {
		t.Fatal("nil")
	}
}
