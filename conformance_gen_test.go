package eid

// testdata/conformance (rp-conformance/1) — RP SDK-уудын (TS, .NET, Java) нийтлэг conformance корпусын генератор.
// Go нь reference: `go test -run TestConformanceCorpus -update-conformance` бүх файлыг дахин бичнэ; энгийн
// `go test` нь санах ойд дахин үүсгээд диск дээрхтэй байт-ижил эсэхийг шалгана (хуучирсан корпус → улаан).
//
// Тогтвортой байдал: түлхүүр нь pki/keys/*.key.pem (тестийн, бодит гинжид итгэгдэхгүй; байхгүй бол зөвхөн -update
// үүсгэнэ), цаг confNow, гэрчилгээ/OCSP-ийг RSA PKCS#1 v1.5 (детерминист) зурна, RSA-PSS-ийн salt нь digest-ээс
// гаргасан тогтмол утга (confPSSSign), ECDSA нь RFC 6979 (PrivateKey.Sign(nil, …)). README.md ба
// eidlogin/scenarios.json нь гараар бичигдсэн — манифестэд hash-аар л орно.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	confDir     = "testdata/conformance"
	confVersion = "rp-conformance/1"
	confRPName  = "Тест банк"
	confRPUUID  = "00000000-0000-4000-8000-000000000001"
	confSecret  = "rp_sk_conformance_test"
	confBaseURL = "https://rp.conformance.test"
	confOCSPURL = "http://ocsp.conformance.test/ocsp"
	confETSI    = "PNOMN-999999990001"
	confDocNo   = "PNOMN-999999990001-MOCK-Q"
	confSID     = "0b5e6a4c-1d2e-4f3a-8b9c-0d1e2f3a4b5c"
	confCallbck = "https://rp.conformance.test/auth/eid/callback"
)

var (
	confNow       = time.Date(2026, 10, 14, 4, 0, 0, 0, time.UTC)
	confNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	confNotAfter  = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	// Гараар бичигдсэн (генератор эзэмшдэггүй) файлууд — манифестэд hash-аар.
	confAuthored = []string{"README.md", "eidlogin/scenarios.json"}
)

type confGen struct {
	t      *testing.T
	update bool
	out    map[string][]byte
	keys   map[string]crypto.Signer
	serial int64
}

func confJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (g *confGen) putJSON(path string, v any) { g.out[path] = confJSON(v) }

// generateConformance — корпусыг бүхэлд нь санах ойд угсарна (зам → байт, confDir-ээс харьцангуй).
func generateConformance(t *testing.T, update bool) map[string][]byte {
	t.Helper()
	g := &confGen{t: t, update: update, out: map[string][]byte{}, keys: map[string]crypto.Signer{}}
	p := g.pki()
	g.rpValidate(p)
	g.ocspScenarios(p)
	g.interactions()
	g.acsp()
	g.wire(p)
	g.manifest()
	return g.out
}

// ── түлхүүр, гэрчилгээ ──

func (g *confGen) key(name string, ec bool) crypto.Signer {
	if k, ok := g.keys[name]; ok {
		return k
	}
	path := "pki/keys/" + name + ".key.pem"
	b, err := os.ReadFile(filepath.Join(confDir, path))
	if errors.Is(err, fs.ErrNotExist) {
		if !g.update {
			g.t.Fatalf("%s алга — `go test -run TestConformanceCorpus -update-conformance`", path)
		}
		var k crypto.Signer
		if ec {
			k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		} else {
			k, err = rsa.GenerateKey(rand.Reader, 2048)
		}
		if err != nil {
			g.t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			g.t.Fatal(err)
		}
		b = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	} else if err != nil {
		g.t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		g.t.Fatalf("%s: PEM биш", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		g.t.Fatal(err)
	}
	g.out[path] = b
	g.keys[name] = k.(crypto.Signer)
	return g.keys[name]
}

type confCert struct {
	name string
	cert *x509.Certificate
	key  crypto.Signer
}

func (c *confCert) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw}))
}

func (c *confCert) b64() string { return base64.StdEncoding.EncodeToString(c.cert.Raw) }

// mk — тогтмол serial (дарааллаар), хугацаа (өгөөгүй бол confNotBefore…confNotAfter), RSA PKCS#1 v1.5 гарын үсэг.
func (g *confGen) mk(name string, tmpl *x509.Certificate, parent *confCert, key crypto.Signer) *confCert {
	g.serial++
	tmpl.SerialNumber = big.NewInt(0x1000 + g.serial)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore, tmpl.NotAfter = confNotBefore, confNotAfter
	}
	pc, pk := tmpl, key
	if parent != nil {
		pc, pk = parent.cert, parent.key
	}
	if _, ok := pk.(*rsa.PrivateKey); !ok {
		g.t.Fatalf("%s: олгогчийн түлхүүр RSA биш (детерминист бус гарын үсэг)", name)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, key.Public(), pk)
	if err != nil {
		g.t.Fatalf("%s: %v", name, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		g.t.Fatal(err)
	}
	return &confCert{name: name, cert: c, key: key}
}

func confPolicy() []x509.OID {
	o, err := x509.OIDFromInts([]uint64{2, 16, 496, 1, 101, 1, 2, 8})
	if err != nil {
		panic(err)
	}
	return []x509.OID{o}
}

func confCA(cn string, pathLen int) *x509.Certificate {
	c := &x509.Certificate{
		Subject: pkix.Name{Country: []string{"MN"}, Organization: []string{"TEST ONLY"}, CommonName: cn},
		IsCA:    true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, Policies: confPolicy(),
	}
	if pathLen == 0 {
		c.MaxPathLenZero = true
	} else {
		c.MaxPathLen = -1
	}
	return c
}

// confLeafSubject — иргэний subject (тестийн, бодит хүн биш).
func confLeafSubject() pkix.Name {
	return pkix.Name{
		Country: []string{"MN"}, CommonName: "TESTOV TEST", SerialNumber: confETSI,
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "TESTOV"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "TEST"},
		},
	}
}

type leafProfile int

const (
	profAuth      leafProfile = iota // P-CITIZEN-AUTH: KU DS|KE, EKU clientAuth+emailProtection → QUALIFIED
	profSign                         // P-CITIZEN-SIGN: KU DS|CC, EKU emailProtection, QcCompliance → QUALIFIED
	profSignQSCD                     // + QcSSCD → QSCD
	profSignNoQC                     // токены хуучин SIGN: qcStatements алга → ADVANCED
	profTokenAuth                    // P-CITIZEN-AUTH-TOKEN: KU DS, EKU clientAuth+emailProtection, policy → QUALIFIED
)

func confLeaf(p leafProfile) *x509.Certificate {
	c := &x509.Certificate{
		Subject: confLeafSubject(), BasicConstraintsValid: true, Policies: confPolicy(),
		OCSPServer: []string{confOCSPURL},
	}
	switch p {
	case profAuth:
		c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
	case profTokenAuth:
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
	default:
		c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		switch p {
		case profSign:
			c.ExtraExtensions = []pkix.Extension{qcStatementsExt(false)}
		case profSignQSCD:
			c.ExtraExtensions = []pkix.Extension{qcStatementsExt(true)}
		}
	}
	return c
}

type confPKI struct {
	root, ca02, ca04, ca05, caNC, caCrit, caInhibit, caEKU, caExpired, subCA *confCert
	leaves                                                                   map[string]*confCert
	responder, responderNoEKU                                                *confCert
}

func (g *confGen) pki() *confPKI {
	p := &confPKI{leaves: map[string]*confCert{}}
	rootT := confCA("TEST ONLY Conformance Root CA", -1)
	rootT.KeyUsage |= x509.KeyUsageDigitalSignature
	rootT.Policies = nil
	p.root = g.mk("01-root", rootT, nil, g.key("root", false))
	p.ca02 = g.mk("02-national", confCA("TEST ONLY Conformance National Issuing CA", -1), p.root, g.key("ca02", false))
	p.ca04 = g.mk("04-eid", confCA("TEST ONLY Conformance eID Issuing CA", 0), p.ca02, g.key("ca04", false))
	p.ca05 = g.mk("05-other", confCA("TEST ONLY Conformance Organisation Issuing CA", 0), p.ca02, g.key("ca05", false))
	nc := confCA("TEST ONLY Name-Constrained CA", 0)
	nc.PermittedDNSDomains = []string{"example.test"} // leaf-д нэр алга → Go-ийн RFC 5280 шалгалт хангагдана
	p.caNC = g.mk("ca-name-constraints", nc, p.ca02, g.key("ca-nc", false))
	crit := confCA("TEST ONLY Unknown-Critical CA", 0)
	crit.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{0x05, 0x00}}}
	p.caCrit = g.mk("ca-unknown-critical", crit, p.ca02, g.key("ca-crit", false))
	inh := confCA("TEST ONLY Inhibit-AnyPolicy CA", 0)
	inh.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 54}, Critical: true, Value: []byte{0x02, 0x01, 0x00}}}
	p.caInhibit = g.mk("ca-critical-inhibit-any-policy", inh, p.ca02, g.key("ca-inhibit", false))
	ekuT := confCA("TEST ONLY TLS-Only CA", 0)
	ekuT.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	p.caEKU = g.mk("ca-eku-server-auth", ekuT, p.ca02, g.key("ca-eku", false))
	expT := confCA("TEST ONLY Expired CA", 0)
	expT.NotBefore, expT.NotAfter = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p.caExpired = g.mk("ca-expired", expT, p.ca02, g.key("ca-expired", false))
	p.subCA = g.mk("ca-below-pathlen-zero", confCA("TEST ONLY Rogue Sub CA", -1), p.ca04, g.key("ca-sub", false))

	rsaLeaf, ecLeaf := g.key("leaf-rsa", false), g.key("leaf-ec", true)
	add := func(name string, tmpl *x509.Certificate, issuer *confCert, k crypto.Signer) {
		p.leaves[name] = g.mk(name, tmpl, issuer, k)
	}
	add("auth", confLeaf(profAuth), p.ca04, rsaLeaf)
	add("sign", confLeaf(profSign), p.ca04, rsaLeaf)
	add("sign-qscd", confLeaf(profSignQSCD), p.ca04, rsaLeaf)
	add("sign-no-qc", confLeaf(profSignNoQC), p.ca04, rsaLeaf)
	add("sign-ec", confLeaf(profSign), p.ca04, ecLeaf)
	add("token-auth-ec", confLeaf(profTokenAuth), p.ca04, ecLeaf)
	noDS := confLeaf(profAuth)
	noDS.KeyUsage = x509.KeyUsageKeyEncipherment
	add("auth-no-digital-signature", noDS, p.ca04, rsaLeaf)
	wrongEKU := confLeaf(profSign)
	wrongEKU.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	add("sign-eku-server-auth", wrongEKU, p.ca04, rsaLeaf)
	qcBad := confLeaf(profSign)
	qcBad.ExtraExtensions = []pkix.Extension{{Id: oidQcStatementsExt, Value: []byte{0x30, 0x03, 0x06, 0x01, 0x00}}}
	add("sign-qc-malformed", qcBad, p.ca04, rsaLeaf)
	leafCrit := confLeaf(profAuth)
	leafCrit.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}, Critical: true, Value: []byte{0x05, 0x00}}}
	add("auth-unknown-critical", leafCrit, p.ca04, rsaLeaf)
	expired := confLeaf(profAuth)
	expired.NotBefore, expired.NotAfter = confNotBefore, confNow.Add(-30*time.Second)
	add("auth-expired-30s", expired, p.ca04, rsaLeaf)
	future := confLeaf(profAuth)
	future.NotBefore, future.NotAfter = confNow.Add(30*time.Second), confNotAfter
	add("auth-not-yet-valid-30s", future, p.ca04, rsaLeaf)
	edge := confLeaf(profAuth)
	edge.NotBefore, edge.NotAfter = confNotBefore, confNow
	add("auth-not-after-now", edge, p.ca04, rsaLeaf)
	add("auth-under-05", confLeaf(profAuth), p.ca05, rsaLeaf)
	add("auth-under-name-constraints", confLeaf(profAuth), p.caNC, rsaLeaf)
	add("auth-under-unknown-critical", confLeaf(profAuth), p.caCrit, rsaLeaf)
	add("auth-under-inhibit-any-policy", confLeaf(profAuth), p.caInhibit, rsaLeaf)
	add("auth-under-eku-server-auth", confLeaf(profAuth), p.caEKU, rsaLeaf)
	add("sign-under-eku-server-auth", confLeaf(profSign), p.caEKU, rsaLeaf)
	add("auth-under-expired-ca", confLeaf(profAuth), p.caExpired, rsaLeaf)
	add("auth-below-pathlen", confLeaf(profAuth), p.subCA, rsaLeaf)

	// OCSP delegated responder (04-ийн олгосон, id-kp-OCSPSigning) ба EKU-гүй хувилбар.
	resp := &x509.Certificate{Subject: pkix.Name{Country: []string{"MN"}, CommonName: "TEST ONLY Conformance OCSP Responder"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, BasicConstraintsValid: true}
	p.responder = g.mk("ocsp-responder", resp, p.ca04, g.key("ocsp-responder", false))
	respNo := &x509.Certificate{Subject: pkix.Name{Country: []string{"MN"}, CommonName: "TEST ONLY Conformance Responder Without EKU"},
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	p.responderNoEKU = g.mk("ocsp-responder-no-eku", respNo, p.ca04, g.key("ocsp-responder", false))

	for _, c := range []*confCert{p.root, p.ca02, p.ca04, p.ca05, p.caNC, p.caCrit, p.caInhibit, p.caEKU, p.caExpired, p.subCA, p.responder, p.responderNoEKU} {
		g.out["pki/"+c.name+".pem"] = []byte(c.pem())
	}
	for name, c := range p.leaves {
		g.out["pki/leaf-"+name+".pem"] = []byte(c.pem())
	}
	return p
}

// ── гарын үсэг (детерминист) ──

func confHash(name string) crypto.Hash {
	h, err := cryptoHash(name)
	if err != nil {
		panic(err)
	}
	return h
}

func confDigest(h crypto.Hash, b []byte) []byte {
	d := h.New()
	d.Write(b)
	return d.Sum(nil)
}

func confMGF1(h crypto.Hash, seed []byte, n int) []byte {
	var out []byte
	for i := uint32(0); len(out) < n; i++ {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], i)
		d := h.New()
		d.Write(seed)
		d.Write(c[:])
		out = d.Sum(out)
	}
	return out[:n]
}

// confPSSSign — RSASSA-PSS (RFC 8017 §9.1.1, sLen = hLen), salt = H("rp-conformance salt" ‖ digest) — тогтмол.
func confPSSSign(k *rsa.PrivateKey, h crypto.Hash, digest []byte) []byte {
	hLen := h.Size()
	salt := confDigest(h, append([]byte("rp-conformance salt"), digest...))[:hLen]
	emBits := k.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	mp := h.New()
	mp.Write(make([]byte, 8))
	mp.Write(digest)
	mp.Write(salt)
	hh := mp.Sum(nil)
	db := make([]byte, emLen-hLen-1)
	db[emLen-2*hLen-2] = 0x01
	copy(db[emLen-2*hLen-1:], salt)
	mask := confMGF1(h, hh, len(db))
	for i := range db {
		db[i] ^= mask[i]
	}
	db[0] &= 0xff >> (8*emLen - emBits)
	em := append(append(db, hh...), 0xbc)
	s := new(big.Int).Exp(new(big.Int).SetBytes(em), k.D, k.N)
	out := make([]byte, (k.N.BitLen()+7)/8)
	s.FillBytes(out)
	if rsa.VerifyPSS(&k.PublicKey, h, digest, out, &rsa.PSSOptions{SaltLength: hLen}) != nil {
		panic("confPSSSign: өөрийн гарын үсэг шалгагдсангүй")
	}
	return out
}

// confSign — алгоритм/түлхүүр/digest-ийн урт таарахгүй (сөрөг тохиолдол) бол "AA==" (validator гарын үсэг хүртэл
// хүрэхгүй).
func confSign(k crypto.Signer, alg string, h crypto.Hash, digest []byte) string {
	var sig []byte
	var err error
	rk, isRSA := k.(*rsa.PrivateKey)
	ek, isEC := k.(*ecdsa.PrivateKey)
	switch {
	case len(digest) != h.Size():
		return "AA=="
	case alg == string(AlgRSASSAPSS) && isRSA:
		sig = confPSSSign(rk, h, digest)
	case alg == string(AlgECDSAWithSHA256) && isEC:
		sig, err = ek.Sign(nil, digest, crypto.SHA256) // nil → RFC 6979 (детерминист)
	case strings.HasSuffix(alg, "WithRSAEncryption") && isRSA:
		sig, err = rsa.SignPKCS1v15(nil, rk, h, digest)
	default:
		return "AA=="
	}
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// ── rp-validate/1 ──

type confTrust struct {
	Anchors           []string `json:"anchors"`
	Intermediates     []string `json:"intermediates"`
	AllowedIssuerSKIs []string `json:"allowedIssuerSkis"`
	RequiredLevel     string   `json:"requiredLevel,omitempty"`
	ClockSkewSeconds  int      `json:"clockSkewSeconds,omitempty"`
}

type confExpectOK struct {
	DocumentNumber     string            `json:"documentNumber"`
	CertificateLevel   string            `json:"certificateLevel"`
	CertificateSHA256  string            `json:"certificateSha256"`
	Subject            map[string]string `json:"subject"`
	SignatureAlgorithm string            `json:"signatureAlgorithm,omitempty"`
}

type confExpectErr struct {
	Class     string `json:"class"`
	Reason    string `json:"reason,omitempty"`
	EndResult string `json:"endResult,omitempty"`
}

type confExpect struct {
	OK    *confExpectOK  `json:"ok,omitempty"`
	Error *confExpectErr `json:"error,omitempty"`
}

type confValidateCase struct {
	Name    string         `json:"name"`
	Comment string         `json:"comment,omitempty"`
	Kind    string         `json:"kind"`
	Trust   string         `json:"trust"`
	Now     string         `json:"now"`
	Session map[string]any `json:"session"`
	ACSP    *ACSPContext   `json:"acsp,omitempty"`
	Digest  string         `json:"digest,omitempty"`
	Hash    string         `json:"hashAlgorithm,omitempty"`
	Options map[string]any `json:"options,omitempty"`
	SessID  string         `json:"certChoiceSessionId,omitempty"`
	Expect  confExpect     `json:"expect"`
}

func confErr(reason string) confExpect {
	return confExpect{Error: &confExpectErr{Class: "ValidationError", Reason: reason}}
}

func confFailed(endResult string) confExpect {
	return confExpect{Error: &confExpectErr{Class: "SessionFailedError", EndResult: endResult}}
}

func confOK(c *confCert, level, alg string) confExpect {
	s := ParseSubject(c.cert)
	sum := sha256.Sum256(c.cert.Raw)
	return confExpect{OK: &confExpectOK{DocumentNumber: confDocNo, CertificateLevel: level, CertificateSHA256: hex.EncodeToString(sum[:]),
		SignatureAlgorithm: alg, Subject: map[string]string{"serialNumber": s.SerialNumber, "givenName": s.GivenName,
			"surname": s.Surname, "country": s.Country, "commonName": s.CommonName}}}
}

var (
	confRPChallenge  = base64.StdEncoding.EncodeToString(confDigest(crypto.SHA512, []byte("rp-conformance rpChallenge")))
	confServerRandom = base64.StdEncoding.EncodeToString(confDigest(crypto.SHA256, []byte("rp-conformance serverRandom"))[:24])
	confVerifier     = "cnAtY29uZm9ybWFuY2UtdmVyaWZpZXItMDAwMDAwMDAx"
	confInteractions = []Interaction{{Type: "displayTextAndPIN", DisplayText60: "Тест банкинд нэвтрэх"}}
)

// authSpec — ACSP_V2 auth тохиолдол. Хоосон талбар = анхдагч.
type authSpec struct {
	name, comment, trust string
	leaf                 string
	alg, hash            string   // ACSP (RP-ийн хүссэн); "" = rsassa-pss / SHA-512
	respAlg              string   // хариуны signatureAlgorithm; "" = alg
	respParams           any      // хариуны signatureAlgorithmParameters; nil = {hashAlgorithm: hash} (pss-д)
	flow                 string   // хариуны flowType; "" = QR
	flows                []string // ACSP санал болгосон; nil = [QR]
	callback             string   // RP-ийн initialCallbackUrl
	respCallback         *string  // хариуны signature.initialCallbackUrl; nil = протоколын зөв утга
	opts                 map[string]any
	claimed              string // cert.certificateLevel; "" = QUALIFIED
	mutate               func(s map[string]any)
	expect               confExpect
}

func (g *confGen) session(leaf *confCert, proto, claimed string, sig map[string]any) map[string]any {
	if claimed == "" {
		claimed = "QUALIFIED"
	}
	sig["signatureProtocol"] = proto
	return map[string]any{
		"state":             StateComplete,
		"result":            map[string]any{"endResult": EndResultOK, "documentNumber": confDocNo},
		"signatureProtocol": proto,
		"signature":         sig,
		"cert":              map[string]any{"value": leaf.b64(), "certificateLevel": claimed},
	}
}

func (g *confGen) authCase(p *confPKI, s authSpec) confValidateCase {
	leaf := p.leaves[orDefault(s.leaf, "auth")]
	alg, hash := orDefault(s.alg, string(AlgRSASSAPSS)), orDefault(s.hash, string(SHA512))
	respAlg := orDefault(s.respAlg, alg)
	flow := orDefault(s.flow, string(FlowQR))
	flows := []FlowType{FlowQR}
	if s.flows != nil {
		flows = nil
		for _, f := range s.flows {
			flows = append(flows, FlowType(f))
		}
	}
	ib64, err := InteractionsToBase64(confInteractions)
	if err != nil {
		g.t.Fatal(err)
	}
	acsp := &ACSPContext{RPChallenge: confRPChallenge, RelyingPartyName: confRPName, Interactions: ib64,
		InitialCallbackURL: s.callback, FlowTypes: flows, SignatureAlgorithm: SignatureAlgorithm(alg), HashAlgorithm: HashAlgorithm(hash)}
	sameDevice := flow == string(FlowWeb2App) || flow == string(FlowApp2App)
	uc := UserChallengeOf("rp-conformance user challenge verifier (cross-device)")
	if sameDevice {
		uc = UserChallengeOf(confVerifier)
	}
	signedCB := ""
	if sameDevice {
		signedCB = s.callback
	}
	payload := BuildACSPV2Payload(ACSPV2Params{ServerRandom: confServerRandom, RPChallenge: confRPChallenge, UserChallenge: uc,
		RelyingPartyName: confRPName, Interactions: ib64, InteractionTypeUsed: "displayTextAndPIN", InitialCallbackURL: signedCB,
		FlowType: flow})
	sigHash := hash
	if respAlg == string(AlgECDSAWithSHA256) {
		sigHash = string(SHA256)
	}
	h := confHash(sigHash)
	sig := map[string]any{
		"value":              confSign(leaf.key, respAlg, h, confDigest(h, payload)),
		"signatureAlgorithm": respAlg,
		"serverRandom":       confServerRandom,
		"userChallenge":      uc,
		"flowType":           flow,
		"initialCallbackUrl": signedCB,
	}
	if s.respCallback != nil {
		sig["initialCallbackUrl"] = *s.respCallback
	}
	switch {
	case s.respParams != nil:
		sig["signatureAlgorithmParameters"] = s.respParams
	case respAlg == string(AlgRSASSAPSS):
		sig["signatureAlgorithmParameters"] = map[string]any{"hashAlgorithm": hash}
	}
	sess := g.session(leaf, "ACSP_V2", s.claimed, sig)
	sess["interactionTypeUsed"] = "displayTextAndPIN"
	if s.mutate != nil {
		s.mutate(sess)
	}
	return confValidateCase{Name: s.name, Comment: s.comment, Kind: "auth", Trust: orDefault(s.trust, "default"),
		Now: confNow.Format(time.RFC3339), Session: sess, ACSP: acsp, Options: s.opts, Expect: s.expect}
}

type signSpec struct {
	name, comment, trust string
	leaf                 string
	alg                  string // хариуны signatureAlgorithm; "" = rsassa-pss
	hash                 string // RP-ийн hash; "" = SHA-256
	signHash             string // гарын үсэгт хэрэглэх hash; "" = hash
	digestLen            int    // 0 = hash-ийн урт
	opts                 map[string]any
	claimed              string
	mutate               func(s map[string]any)
	expect               confExpect
}

func (g *confGen) signCase(p *confPKI, s signSpec) confValidateCase {
	leaf := p.leaves[orDefault(s.leaf, "sign")]
	alg, hash := orDefault(s.alg, string(AlgRSASSAPSS)), orDefault(s.hash, string(SHA256))
	sh := confHash(orDefault(s.signHash, hash))
	digest := confDigest(sh, []byte("rp-conformance document "+s.name))
	if s.digestLen > 0 {
		digest = digest[:s.digestLen]
	}
	sig := map[string]any{
		"value":              confSign(leaf.key, alg, sh, digest),
		"signatureAlgorithm": alg,
		"flowType":           string(FlowNotification),
	}
	if alg == string(AlgRSASSAPSS) {
		sig["signatureAlgorithmParameters"] = map[string]any{"hashAlgorithm": orDefault(s.signHash, hash)}
	}
	sess := g.session(leaf, "RAW_DIGEST_SIGNATURE", s.claimed, sig)
	if s.mutate != nil {
		s.mutate(sess)
	}
	return confValidateCase{Name: s.name, Comment: s.comment, Kind: "sign", Trust: orDefault(s.trust, "default"),
		Now: confNow.Format(time.RFC3339), Session: sess, Digest: base64.StdEncoding.EncodeToString(digest), Hash: hash,
		Options: s.opts, Expect: s.expect}
}

func sigOf(s map[string]any) map[string]any { return s["signature"].(map[string]any) }

func (g *confGen) rpValidate(p *confPKI) {
	inter := []string{}
	for _, c := range []*confCert{p.ca02, p.ca04, p.ca05, p.caNC, p.caCrit, p.caInhibit, p.caEKU, p.caExpired, p.subCA} {
		inter = append(inter, "pki/"+c.name+".pem")
	}
	ski := []string{hex.EncodeToString(p.ca04.cert.SubjectKeyId)}
	def := confTrust{Anchors: []string{"pki/" + p.root.name + ".pem"}, Intermediates: inter, AllowedIssuerSKIs: ski}
	skew := def
	skew.ClockSkewSeconds = 60
	adv := def
	adv.RequiredLevel = "ADVANCED"
	no02 := def
	no02.Intermediates = inter[1:]
	noAnchor := def
	noAnchor.Anchors = []string{}
	trust := map[string]confTrust{"default": def, "skew-60s": skew, "advanced": adv, "missing-02": no02, "no-anchor": noAnchor}

	str := func(s string) *string { return &s }
	evil := "https://evil.example/cb"
	var cases []confValidateCase
	A := func(s authSpec) { cases = append(cases, g.authCase(p, s)) }
	S := func(s signSpec) { cases = append(cases, g.signCase(p, s)) }
	authOK := confOK(p.leaves["auth"], "QUALIFIED", "")

	// auth — амжилт
	A(authSpec{name: "auth-pss-sha512-qr", expect: authOK})
	A(authSpec{name: "auth-pss-sha256-notification", hash: "SHA-256", flow: "Notification", flows: []string{"Notification"},
		opts: map[string]any{"expectedFlowType": "Notification"}, expect: authOK})
	A(authSpec{name: "auth-web2app-verifier", flow: "Web2App", flows: []string{"QR", "App2App", "Web2App"}, callback: confCallbck,
		opts: map[string]any{"expectedFlowType": "Web2App", "userChallengeVerifier": confVerifier}, expect: authOK})
	A(authSpec{name: "auth-callback-field-absent", comment: "хуучин CA: signature.initialCallbackUrl талбар алга → RP-ийн callback (QR-д хоосон)",
		mutate: func(s map[string]any) { delete(sigOf(s), "initialCallbackUrl") }, expect: authOK})
	A(authSpec{name: "auth-sha256withrsa", alg: "sha256WithRSAEncryption", hash: "SHA-256", expect: authOK})
	A(authSpec{name: "auth-token-ec-p256", leaf: "token-auth-ec", alg: "rsassa-pss", hash: "SHA-256", respAlg: "ecdsa-with-SHA256",
		comment: "токены EC P-256 AUTH (P-CITIZEN-AUTH-TOKEN): ecdsa-with-SHA256 хүссэн rsassa-pss-ийн оронд",
		expect:  confOK(p.leaves["token-auth-ec"], "QUALIFIED", "")})
	A(authSpec{name: "auth-claimed-advanced-required-advanced", trust: "advanced", claimed: "ADVANCED",
		expect: confOK(p.leaves["auth"], "ADVANCED", "")})
	A(authSpec{name: "auth-claimed-level-missing", comment: "хариунд certificateLevel алга → гэрчилгээнийх",
		mutate: func(s map[string]any) { delete(s["cert"].(map[string]any), "certificateLevel") }, expect: authOK})
	// auth — хугацааны ирмэг
	A(authSpec{name: "auth-not-after-equals-now", leaf: "auth-not-after-now", expect: confOK(p.leaves["auth-not-after-now"], "QUALIFIED", "")})
	A(authSpec{name: "auth-expired-30s", leaf: "auth-expired-30s", expect: confErr("cert.expired")})
	A(authSpec{name: "auth-expired-30s-skew-60s", leaf: "auth-expired-30s", trust: "skew-60s",
		expect: confOK(p.leaves["auth-expired-30s"], "QUALIFIED", "")})
	A(authSpec{name: "auth-not-yet-valid-30s", leaf: "auth-not-yet-valid-30s", expect: confErr("cert.not_yet_valid")})
	A(authSpec{name: "auth-not-yet-valid-30s-skew-60s", leaf: "auth-not-yet-valid-30s", trust: "skew-60s",
		expect: confOK(p.leaves["auth-not-yet-valid-30s"], "QUALIFIED", "")})
	// auth — урсгал, callback, verifier
	A(authSpec{name: "auth-web2app-missing-verifier", flow: "Web2App", flows: []string{"QR", "App2App", "Web2App"}, callback: confCallbck,
		opts: map[string]any{"expectedFlowType": "Web2App"}, expect: confErr("auth.verifier_required")})
	A(authSpec{name: "auth-web2app-wrong-verifier", flow: "Web2App", flows: []string{"QR", "App2App", "Web2App"}, callback: confCallbck,
		opts:   map[string]any{"expectedFlowType": "Web2App", "userChallengeVerifier": "d3JvbmctdmVyaWZpZXItMDAwMDAwMDAwMDAwMDAwMDAw"},
		expect: confErr("auth.verifier_mismatch")})
	A(authSpec{name: "auth-flow-not-offered", flow: "Web2App", callback: confCallbck, expect: confErr("auth.flow_not_offered")})
	A(authSpec{name: "auth-flow-relay", comment: "QR-аар зурсан хариуг push гэж хүлээсэн (relay)",
		opts: map[string]any{"expectedFlowType": "Notification"}, flows: []string{"QR", "Notification"}, expect: confErr("flow.mismatch")})
	A(authSpec{name: "auth-callback-forged", respCallback: &evil, expect: confErr("auth.callback_url")})
	A(authSpec{name: "auth-web2app-callback-empty", flow: "Web2App", flows: []string{"QR", "App2App", "Web2App"}, callback: confCallbck,
		respCallback: str(""), opts: map[string]any{"expectedFlowType": "Web2App", "userChallengeVerifier": confVerifier},
		expect: confErr("auth.callback_url")})
	// auth — алгоритм
	A(authSpec{name: "auth-alg-downgrade", respAlg: "sha512WithRSAEncryption", expect: confErr("alg.mismatch")})
	A(authSpec{name: "auth-hash-mismatch", respParams: map[string]any{"hashAlgorithm": "SHA-256"}, expect: confErr("alg.hash_mismatch")})
	A(authSpec{name: "auth-pss-salt-length", respParams: map[string]any{"hashAlgorithm": "SHA-512", "saltLength": 32}, expect: confErr("alg.salt_length")})
	A(authSpec{name: "auth-pss-mgf1-hash", respParams: map[string]any{"hashAlgorithm": "SHA-512",
		"maskGenAlgorithm": map[string]any{"algorithm": "id-mgf1", "parameters": map[string]any{"hashAlgorithm": "SHA-256"}}},
		expect: confErr("alg.mgf1")})
	A(authSpec{name: "auth-pss-no-params", respParams: map[string]any{}, expect: confErr("alg.unsupported")})
	A(authSpec{name: "auth-ec-sha512-requested", leaf: "token-auth-ec", respAlg: "ecdsa-with-SHA256", expect: confErr("alg.ecdsa_hash")})
	A(authSpec{name: "auth-ecdsa-on-rsa-cert", hash: "SHA-256", respAlg: "ecdsa-with-SHA256",
		mutate: func(s map[string]any) { sigOf(s)["value"] = "MEUCIQ==" }, expect: confErr("alg.key_mismatch")})
	A(authSpec{name: "auth-unsupported-alg", respAlg: "sha512WithRSAEncryption",
		mutate: func(s map[string]any) { sigOf(s)["signatureAlgorithm"] = "sha1WithRSAEncryption" }, expect: confErr("alg.unsupported")})
	// auth — хариу/гарын үсэг
	A(authSpec{name: "auth-signature-forged", comment: "serverRandom гарын үсэг зурсны дараа солигдсон",
		mutate: func(s map[string]any) {
			sigOf(s)["serverRandom"] = base64.StdEncoding.EncodeToString(confDigest(crypto.SHA256, []byte("other"))[:24])
		}, expect: confErr("auth.signature")})
	A(authSpec{name: "auth-server-random-short", mutate: func(s map[string]any) { sigOf(s)["serverRandom"] = "c2hvcnQ=" },
		expect: confErr("auth.server_random")})
	A(authSpec{name: "auth-user-challenge-malformed", mutate: func(s map[string]any) { sigOf(s)["userChallenge"] = "short" },
		expect: confErr("auth.user_challenge")})
	A(authSpec{name: "auth-interaction-type-missing", mutate: func(s map[string]any) { delete(s, "interactionTypeUsed") },
		expect: confErr("auth.interaction_type_missing")})
	A(authSpec{name: "auth-user-refused", mutate: func(s map[string]any) {
		for k := range s {
			if k != "state" {
				delete(s, k)
			}
		}
		s["result"] = map[string]any{"endResult": "USER_REFUSED"}
	}, expect: confFailed("USER_REFUSED")})
	A(authSpec{name: "auth-running", mutate: func(s map[string]any) {
		for k := range s {
			delete(s, k)
		}
		s["state"] = "RUNNING"
	}, expect: confErr("session.not_complete")})
	A(authSpec{name: "auth-protocol-mismatch", mutate: func(s map[string]any) { s["signatureProtocol"] = "RAW_DIGEST_SIGNATURE" },
		expect: confErr("protocol.mismatch")})
	A(authSpec{name: "auth-certificate-garbage", comment: "cert.value нь X.509 биш → ValidationError (дотоод алдаа биш)",
		mutate: func(s map[string]any) { s["cert"].(map[string]any)["value"] = "AAAA" }, expect: confErr("cert.malformed")})
	A(authSpec{name: "auth-no-certificate", mutate: func(s map[string]any) { delete(s, "cert") }, expect: confErr("response.no_certificate")})
	A(authSpec{name: "auth-no-signature-value", mutate: func(s map[string]any) { delete(sigOf(s), "value") }, expect: confErr("response.no_signature")})
	A(authSpec{name: "auth-no-document-number", mutate: func(s map[string]any) {
		s["result"] = map[string]any{"endResult": "OK"}
	}, expect: confErr("response.no_document_number")})
	// auth — зориулалт, гинж, issuer, түвшин
	A(authSpec{name: "auth-with-sign-certificate", leaf: "sign", expect: confErr("purpose.auth_client_auth")})
	A(authSpec{name: "auth-no-digital-signature", leaf: "auth-no-digital-signature", expect: confErr("purpose.auth_digital_signature")})
	A(authSpec{name: "auth-no-trust-anchor", trust: "no-anchor", expect: confErr("trust.no_anchor")})
	A(authSpec{name: "auth-chain-missing-02", trust: "missing-02", expect: confErr("chain.untrusted")})
	A(authSpec{name: "auth-issuer-05-not-allowed", leaf: "auth-under-05", expect: confErr("issuer.not_allowed")})
	A(authSpec{name: "auth-chain-name-constraints", leaf: "auth-under-name-constraints",
		comment: "fail-closed: CA-д nameConstraints (нэр нь хангасан ч) → татгалзана. Go ≤ v0.31.0 хүлээн авдаг байсан.",
		expect:  confErr("chain.name_constraints")})
	A(authSpec{name: "auth-chain-unknown-critical-ca", leaf: "auth-under-unknown-critical", expect: confErr("chain.critical_extension")})
	A(authSpec{name: "auth-chain-critical-inhibit-any-policy", leaf: "auth-under-inhibit-any-policy",
		comment: "fail-closed: SDK-ийн жагсаалтад байхгүй critical extension (inhibitAnyPolicy) → татгалзана. Go ≤ v0.31.0 хүлээн авдаг байсан.",
		expect:  confErr("chain.critical_extension")})
	A(authSpec{name: "auth-leaf-unknown-critical", leaf: "auth-unknown-critical", expect: confErr("chain.critical_extension")})
	A(authSpec{name: "auth-chain-pathlen", leaf: "auth-below-pathlen", expect: confErr("chain.path_len")})
	A(authSpec{name: "auth-chain-eku-nesting", leaf: "auth-under-eku-server-auth", expect: confErr("chain.eku")})
	A(authSpec{name: "auth-chain-expired-ca", leaf: "auth-under-expired-ca", expect: confErr("chain.expired")})
	A(authSpec{name: "auth-level-claimed-higher", claimed: "QSCD", expect: confErr("level.claimed_higher")})
	A(authSpec{name: "auth-level-insufficient", claimed: "ADVANCED", expect: confErr("level.insufficient")})

	// sign
	signOK := func(leaf, level, alg string) confExpect { return confOK(p.leaves[leaf], level, alg) }
	S(signSpec{name: "sign-pss-sha256", expect: signOK("sign", "QUALIFIED", "rsassa-pss")})
	S(signSpec{name: "sign-pss-sha512", hash: "SHA-512", expect: signOK("sign", "QUALIFIED", "rsassa-pss")})
	S(signSpec{name: "sign-pkcs1-sha256-expected-alg", alg: "sha256WithRSAEncryption",
		opts:   map[string]any{"expectedAlgorithm": "sha256WithRSAEncryption", "expectedFlowType": "Notification"},
		expect: signOK("sign", "QUALIFIED", "sha256WithRSAEncryption")})
	S(signSpec{name: "sign-pkcs1-sha384", alg: "sha384WithRSAEncryption", hash: "SHA-384", expect: signOK("sign", "QUALIFIED", "sha384WithRSAEncryption")})
	S(signSpec{name: "sign-qscd", leaf: "sign-qscd", claimed: "QSCD", expect: signOK("sign-qscd", "QSCD", "rsassa-pss")})
	S(signSpec{name: "sign-ec-legacy", leaf: "sign-ec", alg: "ecdsa-with-SHA256", opts: map[string]any{"expectedAlgorithm": "rsassa-pss"},
		comment: "хуучин threshold-ECDSA credential: хүссэн алгоритмаас үл хамааран ecdsa-with-SHA256 (зөвхөн SHA-256)",
		expect:  signOK("sign-ec", "QUALIFIED", "ecdsa-with-SHA256")})
	S(signSpec{name: "sign-expected-certificate", alg: "sha256WithRSAEncryption",
		opts:   map[string]any{"expectedCertificate": p.leaves["sign"].b64(), "expectedAlgorithm": "sha256WithRSAEncryption"},
		expect: signOK("sign", "QUALIFIED", "sha256WithRSAEncryption")})
	S(signSpec{name: "sign-no-qc-claimed-advanced", leaf: "sign-no-qc", trust: "advanced", claimed: "ADVANCED",
		expect: signOK("sign-no-qc", "ADVANCED", "rsassa-pss")})
	S(signSpec{name: "sign-ec-sha384-requested", leaf: "sign-ec", alg: "ecdsa-with-SHA256", hash: "SHA-384", signHash: "SHA-256",
		expect: confErr("alg.ecdsa_hash")})
	S(signSpec{name: "sign-alg-mismatch", opts: map[string]any{"expectedAlgorithm": "sha256WithRSAEncryption"}, expect: confErr("alg.mismatch")})
	S(signSpec{name: "sign-pkcs1-on-ec-cert", leaf: "sign-ec", alg: "ecdsa-with-SHA256",
		mutate: func(s map[string]any) { sigOf(s)["signatureAlgorithm"] = "sha256WithRSAEncryption" }, expect: confErr("alg.key_mismatch")})
	S(signSpec{name: "sign-hash-mismatch", alg: "sha512WithRSAEncryption", signHash: "SHA-512", expect: confErr("alg.hash_mismatch")})
	S(signSpec{name: "sign-digest-length", alg: "sha384WithRSAEncryption", hash: "SHA-384", digestLen: 32, expect: confErr("sign.digest_length")})
	S(signSpec{name: "sign-signature-other-digest", mutate: func(s map[string]any) {
		sigOf(s)["value"] = confSign(p.leaves["sign"].key, "rsassa-pss", crypto.SHA256, confDigest(crypto.SHA256, []byte("other document")))
	}, expect: confErr("sign.signature")})
	S(signSpec{name: "sign-expected-certificate-mismatch", opts: map[string]any{"expectedCertificate": p.leaves["sign-qscd"].b64()},
		expect: confErr("sign.certificate_mismatch")})
	S(signSpec{name: "sign-flow-relay", opts: map[string]any{"expectedFlowType": "QR"}, expect: confErr("flow.mismatch")})
	S(signSpec{name: "sign-with-auth-certificate", leaf: "auth", expect: confErr("purpose.sign_non_repudiation")})
	S(signSpec{name: "sign-leaf-eku-server-auth", leaf: "sign-eku-server-auth", expect: confErr("chain.eku")})
	S(signSpec{name: "sign-chain-eku-nesting", leaf: "sign-under-eku-server-auth", expect: confErr("chain.eku")})
	S(signSpec{name: "sign-no-qc-claimed-qualified", leaf: "sign-no-qc", expect: confErr("level.claimed_higher")})
	S(signSpec{name: "sign-qc-malformed", leaf: "sign-qc-malformed", expect: confErr("level.qc_malformed")})
	S(signSpec{name: "sign-document-unusable", mutate: func(s map[string]any) {
		s["result"] = map[string]any{"endResult": "DOCUMENT_UNUSABLE"}
	}, expect: confFailed("DOCUMENT_UNUSABLE")})

	// certificate-choice (гарын үсэггүй)
	cc := func(name, leaf string, mutate func(map[string]any), expect confExpect) {
		l := p.leaves[leaf]
		sess := map[string]any{"state": StateComplete, "result": map[string]any{"endResult": EndResultOK, "documentNumber": confDocNo},
			"cert": map[string]any{"value": l.b64(), "certificateLevel": "QUALIFIED"}}
		if mutate != nil {
			mutate(sess)
		}
		cases = append(cases, confValidateCase{Name: name, Kind: "certificateChoice", Trust: "default", Now: confNow.Format(time.RFC3339),
			Session: sess, SessID: "6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5", Expect: expect})
	}
	cc("certchoice-sign-certificate", "sign", nil, confOK(p.leaves["sign"], "QUALIFIED", ""))
	cc("certchoice-auth-certificate", "auth", nil, confErr("purpose.sign_non_repudiation"))
	cc("certchoice-refused", "sign", func(s map[string]any) {
		delete(s, "cert")
		s["result"] = map[string]any{"endResult": "USER_REFUSED_CERT_CHOICE"}
	}, confFailed("USER_REFUSED_CERT_CHOICE"))

	g.putJSON("rp-validate/cases.json", map[string]any{
		"version": "rp-validate/1",
		"comment": "ЗӨВХӨН ТЕСТИЙН PKI (pki/). README.md §rp-validate.",
		"trust":   trust,
		"cases":   cases,
	})
}

// ── OCSP ──

type ocspSpec struct {
	status     int // 0 good, 1 revoked, 2 unknown
	serial     *big.Int
	thisUpdate time.Time
	nextUpdate time.Time // тэг = алга
	signer     *confCert // nil = 04 өөрөө
	embed      []*confCert
	corruptSig bool
}

// confOCSPResponse — RFC 6960 OCSPResponse (successful, BasicOCSPResponse, byKey responderID, SHA-1 CertID). x/crypto
// ocsp.CreateResponse нь producedAt-ийг time.Now()-оор тавьдаг тул гараар угсарна (детерминист).
func confOCSPResponse(issuer *confCert, leaf *confCert, s ocspSpec) []byte {
	signer := s.signer
	if signer == nil {
		signer = issuer
	}
	serial := s.serial
	if serial == nil {
		serial = leaf.cert.SerialNumber
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		panic(err)
	}
	nameHash := sha1.Sum(issuer.cert.RawSubject)
	keyHash := sha1.Sum(spki.PublicKey.RightAlign())
	var signerSPKI struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(signer.cert.RawSubjectPublicKeyInfo, &signerSPKI); err != nil {
		panic(err)
	}
	responderKeyHash := sha1.Sum(signerSPKI.PublicKey.RightAlign())
	gt := func(b *cryptobyte.Builder, t time.Time) { b.AddASN1GeneralizedTime(t.UTC()) }

	var tbs cryptobyte.Builder
	tbs.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { b.AddASN1OctetString(responderKeyHash[:]) })
		gt(b, s.thisUpdate)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // CertID
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26})
						b.AddASN1NULL()
					})
					b.AddASN1OctetString(nameHash[:])
					b.AddASN1OctetString(keyHash[:])
					b.AddASN1BigInt(serial)
				})
				switch s.status {
				case 0:
					b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(*cryptobyte.Builder) {})
				case 1:
					b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { gt(b, s.thisUpdate.Add(-time.Hour)) })
				default:
					b.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(*cryptobyte.Builder) {})
				}
				gt(b, s.thisUpdate)
				if !s.nextUpdate.IsZero() {
					b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { gt(b, s.nextUpdate) })
				}
			})
		})
	})
	tbsDER := tbs.BytesOrPanic()
	digest := sha256.Sum256(tbsDER)
	sig, err := rsa.SignPKCS1v15(nil, signer.key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	if s.corruptSig {
		sig[len(sig)-1] ^= 0x01
	}
	var basic cryptobyte.Builder
	basic.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbsDER)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11})
			b.AddASN1NULL()
		})
		b.AddASN1BitString(sig)
		if len(s.embed) > 0 {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for _, c := range s.embed {
						b.AddBytes(c.cert.Raw)
					}
				})
			})
		}
	})
	var out cryptobyte.Builder
	out.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Enum(0)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1})
				b.AddASN1OctetString(basic.BytesOrPanic())
			})
		})
	})
	return out.BytesOrPanic()
}

type confHTTPReply struct {
	Status      int    `json:"status"`
	ContentType string `json:"contentType,omitempty"`
	BodyB64     string `json:"bodyB64"`
}

type confOCSPCase struct {
	Name        string                   `json:"name"`
	Comment     string                   `json:"comment,omitempty"`
	Now         string                   `json:"now"`
	Certificate string                   `json:"certificate"`
	Issuer      string                   `json:"issuer"`
	HTTP        map[string]confHTTPReply `json:"http"`
	Expect      map[string]string        `json:"expect"`
}

func (g *confGen) ocspScenarios(p *confPKI) {
	leaf := p.leaves["auth"]
	fresh := func(s ocspSpec) ocspSpec {
		if s.thisUpdate.IsZero() {
			s.thisUpdate = confNow.Add(-time.Hour)
			s.nextUpdate = confNow.Add(23 * time.Hour)
		}
		return s
	}
	reply := func(der []byte) map[string]confHTTPReply {
		return map[string]confHTTPReply{"POST " + confOCSPURL: {Status: 200, ContentType: "application/ocsp-response",
			BodyB64: base64.StdEncoding.EncodeToString(der)}}
	}
	var cases []confOCSPCase
	add := func(name, comment string, http map[string]confHTTPReply, status, kind string) {
		e := map[string]string{"status": status}
		if kind != "" {
			e["errorKind"] = kind
		}
		cases = append(cases, confOCSPCase{Name: name, Comment: comment, Now: confNow.Format(time.RFC3339),
			Certificate: "pki/leaf-auth.pem", Issuer: "pki/04-eid.pem", HTTP: http, Expect: e})
	}
	resp := func(s ocspSpec) map[string]confHTTPReply { return reply(confOCSPResponse(p.ca04, leaf, fresh(s))) }
	add("good", "04 өөрөө зурсан good, thisUpdate now−1ц, nextUpdate now+23ц", resp(ocspSpec{}), "good", "")
	add("revoked", "", resp(ocspSpec{status: 1}), "revoked", "")
	add("unknown-is-revoked", "олгогч энэ serial-ийг мэдэхгүй (unknown) → revoked", resp(ocspSpec{status: 2}), "revoked", "")
	add("issuer-embeds-itself", "04 зурсан, хариунд 04-ийн өөрийн гэрчилгээг шигтгэсэн → good", resp(ocspSpec{embed: []*confCert{p.ca04}}), "good", "")
	add("delegated-responder", "04-ийн олгосон id-kp-OCSPSigning responder зурсан, шигтгэсэн", resp(ocspSpec{signer: p.responder,
		embed: []*confCert{p.responder}}), "good", "")
	add("delegated-without-eku", "responder-т OCSPSigning EKU алга", resp(ocspSpec{signer: p.responderNoEKU,
		embed: []*confCert{p.responderNoEKU}}), "unknown", "signature")
	add("stale-49h", "thisUpdate now−49ц (> 48ц), nextUpdate алга", resp(ocspSpec{thisUpdate: confNow.Add(-49 * time.Hour)}), "unknown", "invalid")
	add("max-age-edge-47h", "thisUpdate now−47ц, nextUpdate алга → хүлээн авна", resp(ocspSpec{thisUpdate: confNow.Add(-47 * time.Hour)}), "good", "")
	add("next-update-passed", "", resp(ocspSpec{thisUpdate: confNow.Add(-3 * time.Hour), nextUpdate: confNow.Add(-time.Hour)}), "unknown", "invalid")
	add("future-10m", "thisUpdate now+10мин (> 5мин skew)", resp(ocspSpec{thisUpdate: confNow.Add(10 * time.Minute)}), "unknown", "invalid")
	add("future-skew-4m", "thisUpdate now+4мин (≤ 5мин skew) → хүлээн авна", resp(ocspSpec{thisUpdate: confNow.Add(4 * time.Minute),
		nextUpdate: confNow.Add(24 * time.Hour)}), "good", "")
	add("wrong-serial", "хариу өөр serial-ийн тухай", resp(ocspSpec{serial: big.NewInt(9999)}), "unknown", "invalid")
	add("bad-signature", "", resp(ocspSpec{corruptSig: true}), "unknown", "signature")
	oversize := confOCSPResponse(p.ca04, leaf, fresh(ocspSpec{}))
	oversize = append(oversize, make([]byte, 16<<10)...)
	add("oversize", "хариу 16 KiB-аас их (DER-ийн араас тэг нөхсөн)", reply(oversize), "unknown", "http_status")
	add("http-500", "", map[string]confHTTPReply{"POST " + confOCSPURL: {Status: 500, BodyB64: ""}}, "unknown", "http_status")
	add("no-reply", "replay-д байхгүй хүсэлт → 404", map[string]confHTTPReply{}, "unknown", "http_status")
	trylater := []byte{0x30, 0x03, 0x0a, 0x01, 0x03}
	add("try-later", "responseStatus tryLater (3)", reply(trylater), "unknown", "responder_status")
	g.putJSON("ocsp/cases.json", map[string]any{
		"version": "ocsp-checker/1",
		"comment": "README.md §ocsp. HTTP replay: түлхүүр «METHOD URL», жагсаалтад байхгүй → 404.",
		"cases":   cases,
	})
}

// ── interactions, ACSP ──

func (g *confGen) interactions() {
	type c struct {
		Name         string        `json:"name"`
		Interactions []Interaction `json:"interactions"`
		JSON         string        `json:"json"`
		Base64       string        `json:"base64"`
	}
	in := []struct {
		name string
		v    []Interaction
	}{
		{"smart-id-doc", []Interaction{{Type: "confirmationMessage", DisplayText200: "Longer description of the transaction context"},
			{Type: "displayTextAndPIN", DisplayText60: "Short description of the transaction context"}}},
		{"cyrillic", []Interaction{{Type: "displayTextAndPIN", DisplayText60: "Тест банкинд нэвтрэх — Өө Үү"}}},
		{"html-chars", []Interaction{{Type: "displayTextAndPIN", DisplayText60: "Банк <А&Б> 'x' \"y\""}}},
		{"backslash-and-controls", []Interaction{{Type: "displayTextAndPIN", DisplayText60: "a\\b\\\\c \t\n\r\x01 /"}}},
		{"line-separators", []Interaction{{Type: "x", DisplayText60: "a b c \\u2028 \\ "}}},
		{"both-texts-field-order", []Interaction{{Type: "confirmationMessageAndVerificationCodeChoice", DisplayText60: "60", DisplayText200: "200"}}},
		{"non-bmp-emoji", []Interaction{{Type: "displayTextAndPIN", DisplayText60: "ok 😀 𝄞"}}},
		{"empty-list", []Interaction{}},
	}
	var out []c
	for _, x := range in {
		b64, err := InteractionsToBase64(x.v)
		if err != nil {
			g.t.Fatal(err)
		}
		raw, _ := base64.StdEncoding.DecodeString(b64)
		out = append(out, c{Name: x.name, Interactions: x.v, JSON: string(raw), Base64: b64})
	}
	g.putJSON("interactions_golden.json", map[string]any{
		"version": "interactions/1",
		"comment": "JS JSON.stringify(interactions)-тэй байт-ижил UTF-8 (талбарын дараалал type, displayText60, displayText200; хоосон талбар орохгүй; <>& escape хийхгүй; U+2028/2029 түүхийгээр; зөвхөн \" \\ ба < U+0020 escape) → base64.",
		"cases":   out,
	})
}

func (g *confGen) acsp() {
	type c struct {
		Name          string            `json:"name"`
		Params        map[string]string `json:"params"`
		HashAlgorithm string            `json:"hashAlgorithm"`
		Payload       string            `json:"payload"`
		Digest        string            `json:"digestB64"`
	}
	sk := smartIDVector
	empty := sk
	empty.BrokeredRpName, empty.InitialCallbackURL, empty.FlowType = "", "", "QR"
	custom := sk
	custom.SchemeName, custom.RelyingPartyName = "eid-mongolia", confRPName
	var out []c
	for _, x := range []struct {
		name string
		p    ACSPV2Params
		h    HashAlgorithm
	}{{"smart-id-doc-sha512", sk, SHA512}, {"empty-optional-fields-sha256", empty, SHA256}, {"scheme-and-cyrillic-rp-sha384", custom, SHA384}} {
		d, err := ACSPV2Digest(x.p, x.h)
		if err != nil {
			g.t.Fatal(err)
		}
		params := map[string]string{"schemeName": x.p.SchemeName, "serverRandom": x.p.ServerRandom, "rpChallenge": x.p.RPChallenge,
			"userChallenge": x.p.UserChallenge, "relyingPartyName": x.p.RelyingPartyName, "brokeredRpName": x.p.BrokeredRpName,
			"interactions": x.p.Interactions, "interactionTypeUsed": x.p.InteractionTypeUsed, "initialCallbackUrl": x.p.InitialCallbackURL,
			"flowType": x.p.FlowType}
		out = append(out, c{Name: x.name, Params: params, HashAlgorithm: string(x.h), Payload: string(BuildACSPV2Payload(x.p)),
			Digest: base64.StdEncoding.EncodeToString(d)})
	}
	if out[0].Digest != "pKOjbNl/5Fy8NfrFqsj6pSn8W8O+Ik8rM33QSsbyD3J9qDJvEm90SboUciuY4wHGWa0Pnq8BgT3NJKmJiUDfKg==" {
		g.t.Fatal("Smart-ID ACSP_V2 вектор зөрөв")
	}
	g.putJSON("acsp_v2.json", map[string]any{
		"version": "acsp-v2/1",
		"comment": "ACSP_V2 payload = scheme|ACSP_V2|serverRandom|rpChallenge|userChallenge|b64(rpName)|b64(brokeredRpName)|b64(SHA-256(interactions))|interactionTypeUsed|initialCallbackUrl|flowType (UTF-8); schemeName \"\" = smart-id. digestB64 = base64(HASH(payload)).",
		"cases":   out,
	})
}

// ── wire ──

type confWireCall struct {
	Method string         `json:"method"`
	Args   map[string]any `json:"args"`
}

type confWireRequest struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers"`
	Body     any               `json:"body,omitempty"`
	Volatile map[string]string `json:"volatile,omitempty"`
}

type confWireResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    any               `json:"body"`
}

type confWireCase struct {
	Name     string           `json:"name"`
	Comment  string           `json:"comment,omitempty"`
	Call     confWireCall     `json:"call"`
	Request  confWireRequest  `json:"request"`
	Response confWireResponse `json:"response"`
	Expect   map[string]any   `json:"expect"`
}

// confRecordTransport — нэг хүсэлтийг барьж бэлэн хариу буцаана.
type confRecordTransport struct {
	req  *http.Request
	body []byte
	resp confWireResponse
}

func (r *confRecordTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.req = req
	if req.Body != nil {
		r.body, _ = io.ReadAll(req.Body)
	}
	b, _ := json.Marshal(r.resp.Body)
	if s, ok := r.resp.Body.(string); ok {
		b = []byte(s)
	}
	h := http.Header{"Content-Type": {"application/json"}}
	for k, v := range r.resp.Headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: r.resp.Status, Header: h, Body: io.NopCloser(bytes.NewReader(b)), Request: req,
		ContentLength: int64(len(b))}, nil
}

const confVolatile = "$volatile"

// confPointerSet — JSON Pointer (RFC 6901, "/a/b")-ийн утгыг солино.
func confPointerSet(v any, ptr, val string) {
	parts := strings.Split(strings.TrimPrefix(ptr, "/"), "/")
	m := v.(map[string]any)
	for _, p := range parts[:len(parts)-1] {
		m = m[p].(map[string]any)
	}
	m[parts[len(parts)-1]] = val
}

func confTimeOrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func confACSPJSON(a *ACSPContext, volatile bool) map[string]any {
	m := map[string]any{"relyingPartyName": a.RelyingPartyName, "brokeredRpName": a.BrokeredRpName, "interactions": a.Interactions,
		"initialCallbackUrl": a.InitialCallbackURL, "flowTypes": a.FlowTypes, "signatureAlgorithm": a.SignatureAlgorithm,
		"hashAlgorithm": a.HashAlgorithm, "rpChallenge": a.RPChallenge}
	if volatile {
		m["rpChallenge"] = "$request:/signatureProtocolParameters/rpChallenge"
	}
	return m
}

func confSignJSON(s *SignContext) map[string]any {
	return map[string]any{"digest": s.Digest, "hashAlgorithm": s.HashAlgorithm, "signatureAlgorithm": s.SignatureAlgorithm,
		"relyingPartyName": s.RelyingPartyName, "interactions": s.Interactions, "initialCallbackUrl": s.InitialCallbackURL}
}

// confSessionJSON — SessionResult-ийн хэлний-хамааралгүй хэлбэр (README §wire «parsed session»).
func confSessionJSON(r *SessionResult) map[string]any {
	ns := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	m := map[string]any{
		"state": r.State, "endResult": ns(r.EndResult), "documentNumber": ns(r.DocumentNumber),
		"certificateDerB64": ns(r.CertificateDERB64), "certificateLevel": ns(r.CertificateLevel),
		"signatureValueB64": ns(r.SignatureValueB64), "signatureAlgorithm": ns(r.SignatureAlgorithm),
		"signatureProtocol": ns(r.SignatureProtocol), "serverRandom": ns(r.ServerRandom), "userChallenge": ns(r.UserChallenge),
		"flowType": ns(r.FlowType), "interactionTypeUsed": ns(r.InteractionTypeUsed),
		"initialCallbackUrl": nil, "signatureAlgorithmParameters": nil, "onBehalfOf": nil, "person": nil, "tokenCertificate": nil,
	}
	if r.InitialCallbackURL != nil {
		m["initialCallbackUrl"] = *r.InitialCallbackURL
	}
	if p := r.SignatureAlgorithmParameters; p != nil {
		sp := map[string]any{"hashAlgorithm": p.HashAlgorithm}
		if p.SaltLength != nil {
			sp["saltLength"] = *p.SaltLength
		}
		m["signatureAlgorithmParameters"] = sp
	}
	if o := r.OnBehalfOf; o != nil {
		om := map[string]any{"orgEtsi": o.OrgEtsi, "orgName": ns(o.OrgName), "role": ns(o.Role), "rightType": ns(o.RightType)}
		if o.RoleLabel != "" {
			om["roleLabel"] = o.RoleLabel
		}
		if o.RightTypeLabel != "" {
			om["rightTypeLabel"] = o.RightTypeLabel
		}
		m["onBehalfOf"] = om
	}
	if r.Person != nil {
		b, _ := json.Marshal(r.Person)
		var pm map[string]any
		_ = json.Unmarshal(b, &pm)
		m["person"] = pm
	}
	if tc := r.TokenCertificate; tc != nil {
		b, _ := json.Marshal(tc)
		var tm map[string]any
		_ = json.Unmarshal(b, &tm)
		m["tokenCertificate"] = tm
	}
	return m
}

func confErrJSON(err error) map[string]any {
	var ae *APIError
	var fe *ForbiddenError
	var une *AuthenticationError
	switch {
	case errors.As(err, &ae):
		m := map[string]any{"class": "ApiError", "status": ae.Status, "code": ae.Code}
		if ae.RetryAfter > 0 {
			m["retryAfterSeconds"] = int(ae.RetryAfter / time.Second)
		}
		return m
	case errors.As(err, &fe):
		return map[string]any{"class": "ForbiddenError", "status": 403, "code": fe.Code}
	case errors.As(err, &une):
		return map[string]any{"class": "AuthenticationError", "status": 401, "code": une.Code}
	}
	panic(fmt.Sprintf("confErrJSON: %T %v", err, err))
}

func (g *confGen) wire(p *confPKI) {
	digest := base64.StdEncoding.EncodeToString(confDigest(crypto.SHA256, []byte("rp-conformance wire document")))
	digest512 := base64.StdEncoding.EncodeToString(confDigest(crypto.SHA512, []byte("rp-conformance wire document")))
	inter := []any{map[string]any{"type": "displayTextAndPIN", "displayText60": "Тест банкинд нэвтрэх"}}
	notif := map[string]any{"sessionID": confSID, "vc": map[string]any{"type": "alphaNumeric4", "value": "4927"},
		"expiresAt": "2026-10-14T04:05:00Z"}
	notifNoExp := map[string]any{"sessionID": confSID, "vc": map[string]any{"type": "alphaNumeric4", "value": "4927"}}
	dl := map[string]any{"sessionID": confSID, "sessionToken": "tok_Conformance-0001", "sessionSecret": "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTAwMQ==",
		"deviceLinkBase": "https://eid.conformance.test/dl", "vc": "4927", "expiresAt": "2026-10-14T04:05:00Z"}
	signer := map[string]any{"documentNumber": confDocNo, "certChoiceSessionId": "6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5"}
	signerNoLink := map[string]any{"documentNumber": confDocNo}

	type spec struct {
		name, comment string
		call          confWireCall
		resp          confWireResponse
	}
	ok := func(b any) confWireResponse { return confWireResponse{Status: 200, Body: b} }
	sessionBody := func(m map[string]any) confWireResponse { return ok(m) }
	authCase := g.authCase(p, authSpec{name: "wire", flow: "Web2App", flows: []string{"QR", "App2App", "Web2App"}, callback: confCallbck})
	authSess := authCase.Session
	authSess["onBehalfOf"] = map[string]any{"orgEtsi": "NTRMN-9999999", "orgName": "Тест ХХК", "role": "CEO", "roleLabel": "Гүйцэтгэх захирал",
		"rightType": "FULL", "rightTypeLabel": "Бүрэн"}
	authSess["person"] = map[string]any{"firstName": "Тест", "lastName": "Тестов", "civilId": "999999990001", "birthDate": "1990-01-01",
		"gender": "M", "geID": 0, "regNo": ""}
	signSess := g.signCase(p, signSpec{name: "wire", alg: "sha256WithRSAEncryption"}).Session
	signSess["signature"].(map[string]any)["signatureProtocol"] = "RAW_DIGEST_SIGNATURE"
	delete(signSess, "signatureProtocol")

	specs := []spec{
		{"auth-notification-etsi", "", confWireCall{"auth.notificationByEtsi", map[string]any{"id": confETSI, "interactions": inter}}, ok(notif)},
		{"auth-notification-document-options", "", confWireCall{"auth.notificationByDocument", map[string]any{"documentNumber": confDocNo,
			"interactions": inter, "options": map[string]any{"certificateLevel": "ADVANCED", "hashAlgorithm": "SHA-256",
				"signatureAlgorithm": "sha256WithRSAEncryption", "onBehalfOf": " NTRMN-9999999 "}}}, ok(notifNoExp)},
		{"auth-device-link-anonymous", "", confWireCall{"auth.deviceLinkAnonymous", map[string]any{"interactions": inter}}, ok(dl)},
		{"auth-device-link-anonymous-callback", "callbackUrl → initialCallbackUrl, flowTypes + App2App, Web2App",
			confWireCall{"auth.deviceLinkAnonymous", map[string]any{"interactions": inter, "options": map[string]any{"callbackUrl": " " + confCallbck + " "}}}, ok(dl)},
		{"auth-device-link-etsi", "", confWireCall{"auth.deviceLinkByEtsi", map[string]any{"id": "ДА99999999", "interactions": inter}}, ok(dl)},
		{"sign-digest-etsi", "", confWireCall{"sign.digestByEtsi", map[string]any{"id": confETSI, "digest": digest, "interactions": inter}}, ok(notif)},
		{"sign-digest-document-options", "", confWireCall{"sign.digestByDocument", map[string]any{"documentNumber": confDocNo, "digest": digest512,
			"interactions": inter, "options": map[string]any{"hashAlgorithm": "SHA-512", "signatureAlgorithm": "sha512WithRSAEncryption",
				"fileName": " гэрээ.pdf ", "onBehalfOf": "NTRMN-9999999", "certificateLevel": "QSCD"}}}, ok(notif)},
		{"sign-text-etsi", "digest = base64(SHA-256(UTF-8 text))", confWireCall{"sign.textByEtsi", map[string]any{"id": confETSI,
			"text": "Би зөвшөөрч байна", "interactions": inter}}, ok(notif)},
		{"sign-device-link-etsi-callback", "", confWireCall{"sign.deviceLinkByEtsi", map[string]any{"id": confETSI, "digest": digest,
			"interactions": inter, "options": map[string]any{"callbackUrl": confCallbck}}}, ok(dl)},
		{"sign-device-link-document", "", confWireCall{"sign.deviceLinkByDocument", map[string]any{"documentNumber": confDocNo, "digest": digest,
			"interactions": inter}}, ok(dl)},
		{"sign-digest-for-signer-linked", "certChoiceSessionId → /linked/ + linkedSessionID; анхдагч sha256WithRSAEncryption",
			confWireCall{"sign.digestForSigner", map[string]any{"signer": signer, "digest": digest, "interactions": inter}}, ok(notif)},
		{"sign-digest-for-signer-document", "", confWireCall{"sign.digestForSigner", map[string]any{"signer": signerNoLink, "digest": digest,
			"interactions": inter}}, ok(notif)},
		{"sign-device-link-for-signer", "", confWireCall{"sign.deviceLinkForSigner", map[string]any{"signer": signer, "digest": digest,
			"interactions": inter}}, ok(dl)},
		{"certificate-choice-etsi", "interactions/initialCallbackUrl илгээхгүй", confWireCall{"sign.certificateChoiceByEtsi",
			map[string]any{"id": confETSI, "options": map[string]any{"callbackUrl": confCallbck}}}, ok(notif)},
		{"certificate-choice-device-link", "", confWireCall{"sign.certificateChoiceDeviceLink", map[string]any{}}, ok(dl)},
		{"certificate-choice-device-link-callback", "", confWireCall{"sign.certificateChoiceDeviceLink",
			map[string]any{"options": map[string]any{"callbackUrl": confCallbck, "certificateLevel": "ADVANCED"}}}, ok(dl)},
		{"session-auth-complete", "onBehalfOf, person (geID 0 / хоосон мөр орохгүй)", confWireCall{"session.poll",
			map[string]any{"sessionId": confSID, "serverPollMs": 30000}}, sessionBody(authSess)},
		{"session-sign-complete-protocol-in-signature", "signatureProtocol нь signature дотор л", confWireCall{"session.poll",
			map[string]any{"sessionId": confSID, "serverPollMs": 5000}}, sessionBody(signSess)},
		{"session-running", "", confWireCall{"session.poll", map[string]any{"sessionId": confSID, "serverPollMs": 30000}},
			sessionBody(map[string]any{"state": "RUNNING"})},
		{"session-user-refused", "", confWireCall{"session.poll", map[string]any{"sessionId": confSID, "serverPollMs": 30000}},
			sessionBody(map[string]any{"state": "COMPLETE", "result": map[string]any{"endResult": "USER_REFUSED"}})},
		{"session-empty-blocks", "onBehalfOf orgEtsi-гүй, person хоосон, tokenCertificate status-гүй, pss params hashAlgorithm-гүй → null",
			confWireCall{"session.poll", map[string]any{"sessionId": confSID, "serverPollMs": 30000}},
			sessionBody(map[string]any{"state": "COMPLETE", "result": map[string]any{"endResult": "OK", "documentNumber": confDocNo},
				"signature":  map[string]any{"value": "c2ln", "signatureAlgorithm": "rsassa-pss", "signatureAlgorithmParameters": map[string]any{}},
				"onBehalfOf": map[string]any{"orgName": "x"}, "person": map[string]any{}, "tokenCertificate": map[string]any{}})},
		{"session-token-certificate", "", confWireCall{"session.poll", map[string]any{"sessionId": confSID, "serverPollMs": 30000}},
			sessionBody(map[string]any{"state": "COMPLETE", "result": map[string]any{"endResult": "OK", "documentNumber": confDocNo},
				"tokenCertificate": map[string]any{"status": "ISSUED", "authSerialHex": "0a1b", "signSerialHex": "0c2d"}})},
		{"error-400-code", "", confWireCall{"auth.notificationByEtsi", map[string]any{"id": confETSI, "interactions": inter}},
			confWireResponse{Status: 400, Body: map[string]any{"error": "буруу хүсэлт", "code": "REQUEST_INVALID"}}},
		{"error-403-forbidden-code", "", confWireCall{"auth.notificationByEtsi", map[string]any{"id": confETSI, "interactions": inter,
			"options": map[string]any{"onBehalfOf": "NTRMN-9999999"}}},
			confWireResponse{Status: 403, Body: map[string]any{"error": "төлөөлөх эрхгүй", "code": "REPRESENTATION_DENIED"}}},
		{"error-401", "", confWireCall{"sign.digestByEtsi", map[string]any{"id": confETSI, "digest": digest, "interactions": inter}},
			confWireResponse{Status: 401, Body: map[string]any{"error": "unauthorized"}}},
		{"error-429-retry-after", "", confWireCall{"auth.deviceLinkAnonymous", map[string]any{"interactions": inter}},
			confWireResponse{Status: 429, Headers: map[string]string{"Retry-After": "7"}, Body: map[string]any{"error": "хэт олон", "code": "RATE_LIMITED"}}},
	}

	var out []confWireCase
	for _, s := range specs {
		rt := &confRecordTransport{resp: s.resp}
		c, err := NewClient(Config{BaseURL: confBaseURL, Credentials: Credentials{RPUUID: confRPUUID, RPName: confRPName, APISecret: confSecret},
			HTTPClient: &http.Client{Transport: rt}, Trust: TrustConfig{AllowUntrusted: true}})
		if err != nil {
			g.t.Fatal(err)
		}
		res, err := confInvoke(g.t, c, s.call)
		if rt.req == nil {
			g.t.Fatalf("%s: хүсэлт илгээгдсэнгүй: %v", s.name, err)
		}
		req := confWireRequest{Method: rt.req.Method, Path: rt.req.URL.RequestURI(),
			Headers: map[string]string{"Authorization": rt.req.Header.Get("Authorization")}}
		if ct := rt.req.Header.Get("Content-Type"); ct != "" {
			req.Headers["Content-Type"] = ct
		}
		var expect map[string]any
		if len(rt.body) > 0 {
			var body map[string]any
			if err := json.Unmarshal(rt.body, &body); err != nil {
				g.t.Fatal(err)
			}
			if spp, ok := body["signatureProtocolParameters"].(map[string]any); ok && body["signatureProtocol"] == "ACSP_V2" {
				if b, _ := base64.StdEncoding.DecodeString(spp["rpChallenge"].(string)); len(b) != 64 {
					g.t.Fatalf("%s: rpChallenge %d байт", s.name, len(b))
				}
				confPointerSet(body, "/signatureProtocolParameters/rpChallenge", confVolatile)
				req.Volatile = map[string]string{"/signatureProtocolParameters/rpChallenge": "base64:64"}
			}
			req.Body = body
		}
		if err != nil {
			expect = map[string]any{"error": confErrJSON(err)}
		} else {
			hasExp := false
			if m, ok := s.resp.Body.(map[string]any); ok {
				_, hasExp = m["expiresAt"]
			}
			expect = confWireExpect(res, req.Volatile != nil, hasExp)
		}
		out = append(out, confWireCase{Name: s.name, Comment: s.comment, Call: s.call, Request: req, Response: s.resp, Expect: expect})
	}
	g.putJSON("wire/cases.json", map[string]any{
		"version": "wire/1",
		"comment": "README.md §wire.",
		"client":  map[string]any{"baseUrl": confBaseURL, "rpUUID": confRPUUID, "rpName": confRPName, "apiSecret": confSecret, "defaultCertificateLevel": "QUALIFIED"},
		"cases":   out,
	})
}

func confWireExpect(res any, volatile, hasExp bool) map[string]any {
	switch r := res.(type) {
	case *NotificationSession:
		m := map[string]any{"type": "notification", "sessionId": r.SessionID, "vc": r.VC, "rpChallenge": r.RPChallenge,
			"acsp": nil, "sign": nil}
		if r.ACSP != nil {
			m["acsp"] = confACSPJSON(r.ACSP, volatile)
			m["rpChallenge"] = m["acsp"].(map[string]any)["rpChallenge"]
		}
		if r.Sign != nil {
			m["sign"] = confSignJSON(r.Sign)
		}
		if hasExp {
			m["expiresAt"] = confTimeOrNil(r.ExpiresAt) // зөвхөн CA-ийн expiresAt (алга бол SDK тооцоолно → харьцуулахгүй)
		}
		return m
	case *DeviceLinkSession:
		m := map[string]any{"type": "deviceLink", "sessionId": r.SessionID, "vc": r.VC, "sessionToken": r.SessionToken,
			"sessionSecret": r.SessionSecret, "deviceLinkBase": r.DeviceLinkBase, "sessionType": string(r.SessionType),
			"rpChallenge": r.RPChallenge, "acsp": nil, "sign": nil}
		if hasExp {
			m["expiresAt"] = confTimeOrNil(r.ExpiresAt)
		}
		if r.ACSP != nil {
			m["acsp"] = confACSPJSON(r.ACSP, volatile)
			m["rpChallenge"] = m["acsp"].(map[string]any)["rpChallenge"]
		}
		if r.Sign != nil {
			m["sign"] = confSignJSON(r.Sign)
		}
		if r.SessionType == SessionCert {
			m["relyingPartyName"] = r.RelyingPartyName
			m["callbackUrl"] = r.CallbackURL
		}
		return m
	case *SessionResult:
		return map[string]any{"type": "session", "session": confSessionJSON(r)}
	}
	panic(fmt.Sprintf("confWireExpect: %T", res))
}

// confInvoke — wire call-ийг Go SDK-ийн method руу буулгана (README §wire-ийн method жагсаалт).
func confInvoke(t *testing.T, c *Client, call confWireCall) (any, error) {
	t.Helper()
	ctx := context.Background()
	a := call.Args
	str := func(k string) string { s, _ := a[k].(string); return s }
	var inter []Interaction
	if raw, ok := a["interactions"]; ok {
		b, _ := json.Marshal(raw)
		if err := json.Unmarshal(b, &inter); err != nil {
			t.Fatal(err)
		}
	}
	o, _ := a["options"].(map[string]any)
	opt := func(k string) string { s, _ := o[k].(string); return s }
	authO := &AuthOptions{CertificateLevel: CertificateLevel(opt("certificateLevel")), CallbackURL: opt("callbackUrl"),
		OnBehalfOf: opt("onBehalfOf"), SignatureAlgorithm: SignatureAlgorithm(opt("signatureAlgorithm")), HashAlgorithm: HashAlgorithm(opt("hashAlgorithm"))}
	signO := &SignOptions{CertificateLevel: CertificateLevel(opt("certificateLevel")), CallbackURL: opt("callbackUrl"),
		OnBehalfOf: opt("onBehalfOf"), SignatureAlgorithm: SignatureAlgorithm(opt("signatureAlgorithm")), HashAlgorithm: HashAlgorithm(opt("hashAlgorithm")),
		FileName: opt("fileName")}
	ccO := &CertChoiceOptions{CertificateLevel: CertificateLevel(opt("certificateLevel")), CallbackURL: opt("callbackUrl")}
	signer := func() *Signer {
		m, _ := a["signer"].(map[string]any)
		s := &Signer{}
		s.DocumentNumber, _ = m["documentNumber"].(string)
		s.CertChoiceSessionID, _ = m["certChoiceSessionId"].(string)
		return s
	}
	switch call.Method {
	case "auth.notificationByEtsi":
		return c.Auth.NotificationByEtsi(ctx, str("id"), inter, authO)
	case "auth.notificationByDocument":
		return c.Auth.NotificationByDocument(ctx, str("documentNumber"), inter, authO)
	case "auth.deviceLinkAnonymous":
		return c.Auth.DeviceLinkAnonymous(ctx, inter, authO)
	case "auth.deviceLinkByEtsi":
		return c.Auth.DeviceLinkByEtsi(ctx, str("id"), inter, authO)
	case "sign.digestByEtsi":
		return c.Sign.DigestByEtsi(ctx, str("id"), str("digest"), inter, signO)
	case "sign.digestByDocument":
		return c.Sign.DigestByDocument(ctx, str("documentNumber"), str("digest"), inter, signO)
	case "sign.textByEtsi":
		return c.Sign.TextByEtsi(ctx, str("id"), str("text"), inter, signO)
	case "sign.deviceLinkByEtsi":
		return c.Sign.DeviceLinkByEtsi(ctx, str("id"), str("digest"), inter, signO)
	case "sign.deviceLinkByDocument":
		return c.Sign.DeviceLinkByDocument(ctx, str("documentNumber"), str("digest"), inter, signO)
	case "sign.digestForSigner":
		return c.Sign.DigestForSigner(ctx, signer(), str("digest"), inter, signO)
	case "sign.deviceLinkForSigner":
		return c.Sign.DeviceLinkForSigner(ctx, signer(), str("digest"), inter, signO)
	case "sign.certificateChoiceByEtsi":
		return c.Sign.CertificateChoiceByEtsi(ctx, str("id"), ccO)
	case "sign.certificateChoiceDeviceLink":
		return c.Sign.CertificateChoiceDeviceLink(ctx, ccO)
	case "session.poll":
		ms, _ := a["serverPollMs"].(float64)
		if v, ok := a["serverPollMs"].(int); ok {
			ms = float64(v)
		}
		return c.Session.Poll(ctx, str("sessionId"), time.Duration(ms)*time.Millisecond)
	}
	t.Fatalf("confInvoke: үл мэдэх method %s", call.Method)
	return nil, nil
}

// ── манифест ──

func (g *confGen) manifest() {
	for _, f := range confAuthored {
		b, err := os.ReadFile(filepath.Join(confDir, f))
		if err != nil {
			g.t.Fatalf("гараар бичигдсэн %s: %v", f, err)
		}
		g.out[f] = b
	}
	files := map[string]string{}
	var names []string
	for p, b := range g.out {
		if strings.HasPrefix(p, "pki/keys/") {
			continue
		}
		sum := sha256.Sum256(b)
		files[p] = hex.EncodeToString(sum[:])
		names = append(names, p)
	}
	sort.Strings(names)
	dl, err := os.ReadFile("testdata/devicelink_golden.json")
	if err != nil {
		g.t.Fatal(err)
	}
	dlSum := sha256.Sum256(dl)
	if hex.EncodeToString(dlSum[:]) != devicelinkGoldenSHA256 {
		g.t.Fatal("devicelink_golden.json pinned sha256-аас зөрөв")
	}
	g.putJSON("manifest.json", map[string]any{
		"version": confVersion,
		"comment": "ЗӨВХӨН ТЕСТИЙН өгөгдөл. files = энэ хавтаснаас харьцангуй зам → sha256 (manifest.json өөрөө, pki/keys/ орохгүй). README.md.",
		"now":     confNow.Format(time.RFC3339),
		"files":   files,
		"devicelinkGolden": map[string]any{
			"source": "ca-eidmongolia-mn server/internal/crypto/testdata/devicelink_golden.json (frozen)",
			"goPath": "testdata/devicelink_golden.json",
			"sha256": devicelinkGoldenSHA256,
		},
		"myqrVectors": map[string]any{
			"source": "ca-eidmongolia-mn server/internal/service/memory/testdata/myqr_vectors.json",
			"goPath": "testdata/myqr_vectors.json",
			"sha256": myqrVectorsSHA256,
		},
	})
}
