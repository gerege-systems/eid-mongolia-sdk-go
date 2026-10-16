package eid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// CA-ийн бодит гинжийн профайл (ca-eidmongolia-mn pki/chain/01–04, crypto/ca_profile.go-оос, 2026-10-14):
//
//	01 Root:    KU critical DS|keyCertSign|cRLSign, BC critical CA:TRUE (pathLen алга), EKU алга
//	02 MDDC:    KU critical DS|keyCertSign|cRLSign, BC critical CA:TRUE, policy 2.16.496.1.101.1.2.8, CDP
//	03 Gerege:  KU critical keyCertSign|cRLSign, BC critical CA:TRUE, policy, CDP, AIA
//	04 eID:     KU critical keyCertSign|cRLSign, BC critical CA:TRUE pathlen:0, policy, CDP, AIA
//	leaf AUTH:  KU critical DS|keyEncipherment, BC critical CA:FALSE, EKU clientAuth+emailProtection, policy,
//	            SDA (2.5.29.9), AIA, CDP — бүгд non-critical
//	leaf SIGN:  KU critical DS|contentCommitment, EKU emailProtection, qcStatements (1.3.6.1.5.5.7.1.3) non-critical
//
// Name constraints, policyConstraints, inhibitAnyPolicy, завсрын CA-ийн EKU — гинжинд алга.

var (
	oidNationalPolicy = asn1.ObjectIdentifier{2, 16, 496, 1, 101, 1, 2, 8}
	oidSDA            = asn1.ObjectIdentifier{2, 5, 29, 9}
)

type chainPKI struct {
	root, mddc, gerege, issuing *testCA
}

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func profileCA(cn string, ku x509.KeyUsage, pathLen int) *x509.Certificate {
	c := &x509.Certificate{
		Subject: pkix.Name{Country: []string{"MN"}, CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: ku, PolicyIdentifiers: []asn1.ObjectIdentifier{oidNationalPolicy},
		CRLDistributionPoints: []string{"http://crl.example.test/ca"},
	}
	switch {
	case pathLen == 0:
		c.MaxPathLenZero = true
	case pathLen > 0:
		c.MaxPathLen = pathLen
	default:
		c.MaxPathLen = -1
	}
	return c
}

// realProfilePKI — 01 → 02 → 03 → 04 бодит профайлын хуулбар (түлхүүр нь тестийнх).
func realProfilePKI(t *testing.T) chainPKI {
	t.Helper()
	rk, mk, gk, ik := newKey(t), newKey(t), newKey(t), newKey(t)
	root := profileCA("Test National Root CA", x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign, -1)
	root.PolicyIdentifiers, root.CRLDistributionPoints = nil, nil
	r := mkCert(t, root, nil, &rk.PublicKey, rk)
	m := mkCert(t, profileCA("Test National Issuing CA", x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign, -1), r, &mk.PublicKey, mk)
	g := mkCert(t, profileCA("Test Gerege Issuing CA", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, -1), m, &gk.PublicKey, gk)
	i := mkCert(t, profileCA("Test eID Issuing CA", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, 0), g, &ik.PublicKey, ik)
	return chainPKI{root: r, mddc: m, gerege: g, issuing: i}
}

// citizenLeaf — P-CITIZEN-AUTH / P-CITIZEN-SIGN профайлын leaf.
func citizenLeaf(t *testing.T, issuer *testCA, sign bool, key crypto.Signer) *testCA {
	t.Helper()
	tmpl := leafTmpl()
	tmpl.BasicConstraintsValid = true
	tmpl.PolicyIdentifiers = []asn1.ObjectIdentifier{oidNationalPolicy}
	tmpl.OCSPServer = []string{"http://ocsp.example.test/ocsp"}
	tmpl.IssuingCertificateURL = []string{"http://crl.example.test/ca/issuing.cer"}
	tmpl.CRLDistributionPoints = []string{"http://crl.example.test/crl"}
	sda, _ := asn1.Marshal([]struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 3}, Values: []asn1.RawValue{{Tag: asn1.TagPrintableString, Bytes: []byte("M")}}}})
	tmpl.ExtraExtensions = []pkix.Extension{{Id: oidSDA, Value: sda}}
	if sign {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, qcStatementsExt(false)) // QcCompliance → QUALIFIED
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
	}
	return mkCert(t, tmpl, issuer, key.Public(), key)
}

func chainValidator(t *testing.T, anchor *testCA, inter ...*testCA) *Validator {
	t.Helper()
	var pems []string
	for _, c := range inter {
		pems = append(pems, c.pem)
	}
	v, err := NewValidator(TrustConfig{TrustAnchorsPEM: []string{anchor.pem}, IntermediatesPEM: pems, AllowAnyIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func signResult(t *testing.T, leaf *testCA) (*SessionResult, string) {
	t.Helper()
	digest := sha256.Sum256([]byte("doc"))
	return &SessionResult{State: StateComplete, EndResult: EndResultOK, DocumentNumber: "d", SignatureProtocol: "RAW_DIGEST_SIGNATURE",
		SignatureAlgorithm: "rsassa-pss", SignatureAlgorithmParameters: &SignatureAlgorithmParameters{HashAlgorithm: "SHA-256"},
		SignatureValueB64: signDigest(t, leaf.key, "rsassa-pss", crypto.SHA256, digest[:]), CertificateLevel: "QUALIFIED",
		CertificateDERB64: base64.StdEncoding.EncodeToString(leaf.cert.Raw)}, base64.StdEncoding.EncodeToString(digest[:])
}

// Бодит профайлтай гинж (01 → 02 → 03 → 04 → иргэн) x509.Verify-аар амжина: auth ба sign (v0.6.0: зориулалт анхдагчаар).
func TestChain_RealProfile(t *testing.T) {
	p := realProfilePKI(t)
	v := chainValidator(t, p.root, p.mddc, p.gerege, p.issuing)
	inter := []string{p.mddc.pem, p.gerege.pem, p.issuing.pem}
	loose, err := NewValidator(TrustConfig{TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: inter, AllowAnyIssuer: true,
		SkipKeyUsageCheck: true, RequiredLevel: LevelAdvanced})
	if err != nil {
		t.Fatal(err)
	}
	auth := citizenLeaf(t, p.issuing, false, newKey(t))
	r, acsp := signedAuth(t, "QR", authOpts{leaf: auth})
	if id, err := v.ValidateAuth(r, acsp, ValidateAuthOptions{}); err != nil || id.CertificateLevel != "QUALIFIED" {
		t.Fatal(id, err)
	}
	sign := citizenLeaf(t, p.issuing, true, newKey(t))
	sr, d := signResult(t, sign)
	if vs, err := v.ValidateSign(sr, d, SHA256); err != nil || vs.CertificateLevel != "QUALIFIED" {
		t.Fatal(vs, err)
	}
	// Токены EC P-256 гэрчилгээ (P-CITIZEN-*-TOKEN) — ижил гинж.
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok := citizenLeaf(t, p.issuing, false, ek)
	r, acsp = signedAuth(t, "QR", authOpts{leaf: tok, alg: "ecdsa-with-SHA256"})
	if _, err := v.ValidateAuth(r, acsp, ValidateAuthOptions{}); err != nil {
		t.Fatal(err)
	}
	// Гарын үсгийн гэрчилгээ (EKU emailProtection) нэвтрэлтэд — clientAuth алга → татгалзана.
	r, acsp = signedAuth(t, "QR", authOpts{leaf: sign})
	_, err = v.ValidateAuth(r, acsp, ValidateAuthOptions{})
	wantInvalid(t, err, "clientAuth")
	// Нэвтрэлтийн (PIN1) гэрчилгээ (clientAuth + emailProtection) нь sign-д EKU-гаар тэнцэнэ — v0.6.0-аас KU
	// (nonRepudiation) анхдагчаар шалгагдаж унана (v0.5.x-д CheckKeyUsage=false анхдагч тул тэнцдэг байв).
	ar, ad := signResult(t, auth)
	ar.CertificateLevel = "ADVANCED"
	_, err = v.ValidateSign(ar, ad, SHA256)
	wantInvalid(t, err, "nonRepudiation")
	if _, err := loose.ValidateSign(ar, ad, SHA256); err != nil { // SkipKeyUsageCheck — хуучин зан (зөвлөхгүй)
		t.Fatal(err)
	}
	// Анхдагч issuer allowlist (CitizenIssuingCASKI) — тестийн 04 биш тул татгалзана; өөрийн SKI-гаар амжина.
	def, _ := NewValidator(TrustConfig{TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: inter})
	r, acsp = signedAuth(t, "QR", authOpts{leaf: auth})
	_, err = def.ValidateAuth(r, acsp, ValidateAuthOptions{})
	wantInvalid(t, err, "AllowedIssuerSKIs")
	own, _ := NewValidator(TrustConfig{TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: inter,
		AllowedIssuerSKIs: []string{hex.EncodeToString(p.issuing.cert.SubjectKeyId)}})
	if _, err := own.ValidateAuth(r, acsp, ValidateAuthOptions{}); err != nil {
		t.Fatal(err)
	}
}

// Түвшин гэрчилгээнээс (v0.6.0): SIGN qcStatements → QUALIFIED/QSCD, qc-гүй → ADVANCED; AUTH KE → QUALIFIED, токен → ADVANCED.
func TestCertificateLevelFromCertificate(t *testing.T) {
	p := realProfilePKI(t)
	v := chainValidator(t, p.root, p.mddc, p.gerege, p.issuing)
	adv, _ := NewValidator(TrustConfig{TrustAnchorsPEM: []string{p.root.pem},
		IntermediatesPEM: []string{p.mddc.pem, p.gerege.pem, p.issuing.pem}, AllowAnyIssuer: true, RequiredLevel: LevelAdvanced})
	level := func(c *testCA, proto string) CertificateLevel {
		t.Helper()
		l, err := CertificateLevelOf(c.cert, proto)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	sign := citizenLeaf(t, p.issuing, true, newKey(t))
	if level(sign, "RAW_DIGEST_SIGNATURE") != LevelQualified {
		t.Fatal("SIGN qc")
	}
	sr, d := signResult(t, sign)
	sr.CertificateLevel = "QSCD" // QcSSCD алга — худал
	_, err := v.ValidateSign(sr, d, SHA256)
	wantInvalid(t, err, "гэрчилгээнээс (QUALIFIED) өндөр")
	sr.CertificateLevel = "ADVANCED" // доогуур — хариуных
	_, err = v.ValidateSign(sr, d, SHA256)
	wantInvalid(t, err, "хүрэлцэхгүй")
	if vs, err := adv.ValidateSign(sr, d, SHA256); err != nil || vs.CertificateLevel != "ADVANCED" {
		t.Fatal(vs, err)
	}
	sr.CertificateLevel = "" // алга — гэрчилгээнийх
	if vs, err := v.ValidateSign(sr, d, SHA256); err != nil || vs.CertificateLevel != "QUALIFIED" {
		t.Fatal(vs, err)
	}
	// Токены SIGN (qcStatements үгүй) → ADVANCED: QUALIFIED гэж зарласан хариу татгалзагдана.
	tmpl := leafTmpl()
	tmpl.KeyUsage, tmpl.ExtKeyUsage, tmpl.ExtraExtensions = x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, nil
	k := newKey(t)
	tokSign := mkCert(t, tmpl, p.issuing, &k.PublicKey, k)
	if level(tokSign, "RAW_DIGEST_SIGNATURE") != LevelAdvanced {
		t.Fatal("token SIGN")
	}
	tr, td := signResult(t, tokSign)
	_, err = v.ValidateSign(tr, td, SHA256)
	wantInvalid(t, err, "QUALIFIED гэрчилгээнээс (ADVANCED) өндөр")
	// QcSSCD → QSCD
	tmpl = leafTmpl()
	tmpl.ExtraExtensions = []pkix.Extension{qcStatementsExt(true)}
	qk := newKey(t)
	if level(mkCert(t, tmpl, p.issuing, &qk.PublicKey, qk), "RAW_DIGEST_SIGNATURE") != LevelQSCD {
		t.Fatal("QSCD")
	}
	// Утасны AUTH (KU keyEncipherment) → QUALIFIED; токены AUTH (KU DS) → ADVANCED.
	if level(citizenLeaf(t, p.issuing, false, newKey(t)), "ACSP_V2") != LevelQualified {
		t.Fatal("AUTH")
	}
	tmpl = leafTmpl()
	tmpl.KeyUsage, tmpl.ExtKeyUsage, tmpl.ExtraExtensions = x509.KeyUsageDigitalSignature,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}, nil
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tokAuth := mkCert(t, tmpl, p.issuing, &ek.PublicKey, ek)
	if level(tokAuth, "ACSP_V2") != LevelAdvanced {
		t.Fatal("token AUTH")
	}
	r, acsp := signedAuth(t, "QR", authOpts{leaf: tokAuth, alg: "ecdsa-with-SHA256"})
	_, err = v.ValidateAuth(r, acsp, ValidateAuthOptions{})
	wantInvalid(t, err, "өндөр")
	r.CertificateLevel = "ADVANCED"
	if id, err := adv.ValidateAuth(r, acsp, ValidateAuthOptions{}); err != nil || id.CertificateLevel != "ADVANCED" {
		t.Fatal(id, err)
	}
	// Гэмтсэн qcStatements → *ValidationError
	tmpl = leafTmpl()
	tmpl.ExtraExtensions = []pkix.Extension{{Id: oidQcStatementsExt, Value: []byte{0x30, 0x03, 0x06, 0x01, 0x00}}}
	bk := newKey(t)
	if _, err := CertificateLevelOf(mkCert(t, tmpl, p.issuing, &bk.PublicKey, bk).cert, "RAW_DIGEST_SIGNATURE"); err == nil {
		t.Fatal("гэмтсэн qcStatements")
	}
}

// CitizenIntermediatesPEM — pades/internal/eidcrypto/chain-ийн 02, 03, 04-тэй байт-ижил; 04-ийн SKI = CitizenIssuingCASKI;
// NationalRootCAPEM хүртэл гинжлэгдэнэ; IntermediatesPEM nil бол анхдагч.
func TestCitizenIntermediatesPEM(t *testing.T) {
	for i, f := range []string{"02-mongolian-national-issuing-ca-mddc.pem", "03-gerege-issuing-ca.pem", "04-eid-mongolia-issuing-ca.pem"} {
		b, err := os.ReadFile("pades/internal/eidcrypto/chain/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(b)) != strings.TrimSpace(CitizenIntermediatesPEM[i]) {
			t.Fatalf("%s зөрсөн", f)
		}
	}
	certs, err := parseCerts(append([]string{NationalRootCAPEM}, CitizenIntermediatesPEM[:]...))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i-1]); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if hex.EncodeToString(certs[3].SubjectKeyId) != CitizenIssuingCASKI {
		t.Fatal("04 SKI")
	}
	v, err := NewValidator(TrustConfig{TrustAnchorsPEM: []string{NationalRootCAPEM}})
	if err != nil || len(v.intermediates) != 3 || len(v.allowedIssuers) != 1 || !v.allowedIssuers[CitizenIssuingCASKI] || !v.checkKeyUsage {
		t.Fatal("анхдагч", err)
	}
	if v, _ := NewValidator(TrustConfig{AllowUntrusted: true}); len(v.allowedIssuers) != 0 {
		t.Fatal("AllowUntrusted-д анхдагч allowlist үйлчлэхгүй")
	}
}

// Хуучин гараар угсарсан гинж эдгээрийг (pathLen, завсрын EKU, name constraints, keyCertSign, critical extension)
// шалгадаггүй байсан — бүгд татгалзана.
func TestChain_Rejects(t *testing.T) {
	p := realProfilePKI(t)
	authResult := func(leaf *testCA) (*SessionResult, *ACSPContext) { return signedAuth(t, "QR", authOpts{leaf: leaf}) }

	t.Run("pathLen", func(t *testing.T) {
		// 04 (pathlen:0) доор дахин CA → иргэн.
		sk := newKey(t)
		sub := mkCert(t, profileCA("Rogue Sub CA", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, -1), p.issuing, &sk.PublicKey, sk)
		leaf := citizenLeaf(t, sub, false, newKey(t))
		r, a := authResult(leaf)
		_, err := chainValidator(t, p.root, p.mddc, p.gerege, p.issuing, sub).ValidateAuth(r, a, ValidateAuthOptions{})
		wantInvalid(t, err, "pathLen")
	})
	t.Run("intermediate EKU", func(t *testing.T) {
		k := newKey(t)
		tmpl := profileCA("TLS-only Issuing CA", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, 0)
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		ca := mkCert(t, tmpl, p.gerege, &k.PublicKey, k)
		r, a := authResult(citizenLeaf(t, ca, false, newKey(t)))
		_, err := chainValidator(t, p.root, p.mddc, p.gerege, ca).ValidateAuth(r, a, ValidateAuthOptions{})
		wantInvalid(t, err, "ExtKeyUsage")
		sr, d := signResult(t, citizenLeaf(t, ca, true, newKey(t)))
		_, err = chainValidator(t, p.root, p.mddc, p.gerege, ca).ValidateSign(sr, d, SHA256)
		wantInvalid(t, err, "ExtKeyUsage")
	})
	t.Run("CA:false intermediate", func(t *testing.T) {
		k := newKey(t)
		tmpl := profileCA("Not a CA", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, -1)
		tmpl.IsCA, tmpl.MaxPathLen = false, 0
		notCA := mkCert(t, tmpl, p.gerege, &k.PublicKey, k)
		r, a := authResult(citizenLeaf(t, notCA, false, newKey(t)))
		_, err := chainValidator(t, p.root, p.mddc, p.gerege, notCA).ValidateAuth(r, a, ValidateAuthOptions{})
		wantInvalid(t, err, "гинж")
	})
	t.Run("intermediate without keyCertSign", func(t *testing.T) {
		k := newKey(t)
		ca := mkCert(t, profileCA("CRL-only CA", x509.KeyUsageCRLSign, 0), p.gerege, &k.PublicKey, k)
		r, a := authResult(citizenLeaf(t, ca, false, newKey(t)))
		_, err := chainValidator(t, p.root, p.mddc, p.gerege, ca).ValidateAuth(r, a, ValidateAuthOptions{})
		wantInvalid(t, err, "гинж") // CheckSignatureFrom: KeyUsage-тэй CA-д keyCertSign заавал
	})
	t.Run("expired intermediate", func(t *testing.T) {
		k := newKey(t)
		tmpl := profileCA("Expired Issuing CA", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, 0)
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-72*time.Hour), time.Now().Add(-48*time.Hour)
		ca := mkCert(t, tmpl, p.gerege, &k.PublicKey, k)
		r, a := authResult(citizenLeaf(t, ca, false, newKey(t)))
		_, err := chainValidator(t, p.root, p.mddc, p.gerege, ca).ValidateAuth(r, a, ValidateAuthOptions{})
		wantInvalid(t, err, "гинж")
	})
	t.Run("wrong root", func(t *testing.T) {
		other := realProfilePKI(t)
		r, a := authResult(citizenLeaf(t, p.issuing, false, newKey(t)))
		_, err := chainValidator(t, other.root, p.mddc, p.gerege, p.issuing).ValidateAuth(r, a, ValidateAuthOptions{})
		wantInvalid(t, err, "trust anchor")
	})
	t.Run("missing MDDC intermediate", func(t *testing.T) {
		r, a := authResult(citizenLeaf(t, p.issuing, false, newKey(t)))
		_, err := chainValidator(t, p.root, p.gerege, p.issuing).ValidateAuth(r, a, ValidateAuthOptions{})
		wantInvalid(t, err, "trust anchor")
	})
	t.Run("name constraints", func(t *testing.T) {
		k := newKey(t)
		tmpl := profileCA("Constrained CA", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, 0)
		tmpl.PermittedEmailAddresses = []string{"example.org"}
		ca := mkCert(t, tmpl, p.gerege, &k.PublicKey, k)
		lt := leafTmpl()
		lt.EmailAddresses = []string{"citizen@evil.test"}
		lk := newKey(t)
		r, a := authResult(mkCert(t, lt, ca, &lk.PublicKey, lk))
		_, err := chainValidator(t, p.root, p.mddc, p.gerege, ca).ValidateAuth(r, a, ValidateAuthOptions{})
		wantInvalid(t, err, "name constraints")
	})
	t.Run("unknown critical extension", func(t *testing.T) {
		lt := leafTmpl()
		lt.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{0x05, 0x00}}}
		lk := newKey(t)
		r, a := authResult(mkCert(t, lt, p.issuing, &lk.PublicKey, lk))
		_, err := chainValidator(t, p.root, p.mddc, p.gerege, p.issuing).ValidateAuth(r, a, ValidateAuthOptions{})
		wantInvalid(t, err, "critical")
	})
}

// Бодит нийтийн 04 (testdata) нь 03-аас x509.Verify-аар (pathlen:0, keyCertSign, AKI DirName+serial-тай 03) амжина.
// 02 (MDDC) нийтийн URL-д нийтлэгдээгүй тул 03-ийг энэ тестэд anchor болгоно.
func TestChain_RealPublicCAsVerify(t *testing.T) {
	b4, err := os.ReadFile("testdata/eid-mongolia-issuing-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	b3, err := os.ReadFile("testdata/gerege-issuing-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := parseCerts([]string{string(b4), string(b3)})
	if err != nil {
		t.Fatal(err)
	}
	ca04, ca03 := certs[0], certs[1]
	if !ca04.MaxPathLenZero || ca04.MaxPathLen != 0 || ca04.KeyUsage&x509.KeyUsageCertSign == 0 || len(ca04.ExtKeyUsage) != 0 {
		t.Fatal("04-ийн профайл өөрчлөгдсөн")
	}
	if len(ca04.PermittedDNSDomains)+len(ca04.PermittedEmailAddresses)+len(ca03.PermittedDNSDomains)+len(ca03.PermittedEmailAddresses) != 0 ||
		len(ca04.UnhandledCriticalExtensions)+len(ca03.UnhandledCriticalExtensions) != 0 {
		t.Fatal("гинжинд name constraints / үл таних critical extension гарч ирэв")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca03)
	_, err = ca04.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		t.Fatal(err)
	}
}
