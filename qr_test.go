package eid

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// myqrVectorsSHA256 (MYQR_VECTORS_SHA256) — testdata/myqr_vectors.json-ийн SHA-256 (hex). Файл нь CA-ийн
// server/internal/service/memory/testdata/myqr_vectors.json-тэй байт-ижил хуулбар (CA гэрээ §7.1). Файлыг хуулахдаа
// энд pin хийнэ — хоосон бол файл байгаа үед тест унаж hash-ийг хэвлэнэ.
const myqrVectorsSHA256 = ""

const (
	myqrVectorsFile = "testdata/myqr_vectors.json"
	myqrContractID  = "myqr-2026-10-26"
)

// ── vector-ийн формат (CA гэрээ §7.2; prepare хэсэг — зөвхөн native SDK) ──

type myqrVectorFile struct {
	Contract         string `json:"contract"`
	Issuer           string `json:"issuer"`
	ClockSkewSeconds int64  `json:"clockSkewSeconds"`
	MaxAgeSeconds    int64  `json:"maxAgeSeconds"`
	Limits           struct {
		MaxFields     int `json:"maxFields"`
		MaxKeyChars   int `json:"maxKeyChars"`
		MaxValueBytes int `json:"maxValueBytes"`
		MaxPhotoBytes int `json:"maxPhotoBytes"`
	} `json:"limits"`
	Trust struct {
		AnchorsPEM        []string `json:"anchorsPem"`
		IntermediatesPEM  []string `json:"intermediatesPem"`
		AllowedIssuerSKIs []string `json:"allowedIssuerSkis"`
	} `json:"trust"`
	Parse []struct {
		In    string `json:"in"`
		Token string `json:"token,omitempty"`
		Error string `json:"error,omitempty"`
	} `json:"parse"`
	Verify []myqrVerifyVector `json:"verify"`
}

type myqrVerifyVector struct {
	Name   string `json:"name"`
	JWS    string `json:"jws"`
	Expect struct {
		RPUUID    string `json:"rpUUID"`
		SessionID string `json:"sessionId"`
		Nonce     string `json:"nonce"`
		Issuer    string `json:"issuer,omitempty"`
		Now       int64  `json:"now"`
	} `json:"expect"`
	Revocation map[string]string `json:"revocation"`
	Result     *struct {
		Claims      map[string]any    `json:"claims"`
		DataKeys    []string          `json:"dataKeys"`
		Data        map[string]string `json:"data"`
		Source      string            `json:"source"`
		PhotoSha256 *string           `json:"photoSha256"`
		Signer      struct {
			ETSI       string `json:"etsi"`
			CertSha256 string `json:"certSha256"`
		} `json:"signer"`
		SHA256 string `json:"sha256"`
	} `json:"result,omitempty"`
	Error string `json:"error,omitempty"`
}

// stubRevocation — §7.2: serial (жижиг hex) → good|revoked|unknown; алга бол unknown.
func stubRevocation(m map[string]string) RevocationChecker {
	return func(_ context.Context, cert, _ *x509.Certificate) (RevocationStatus, error) {
		if s, ok := m[strings.ToLower(cert.SerialNumber.Text(16))]; ok {
			return RevocationStatus(s), nil
		}
		return RevocationUnknown, nil
	}
}

func runQRVectors(t *testing.T, f *myqrVectorFile) {
	t.Helper()
	if f.Contract != myqrContractID || f.ClockSkewSeconds != int64(QRClockSkew/time.Second) ||
		f.MaxAgeSeconds != int64(QRMaxAge/time.Second) {
		t.Fatalf("vector-ийн толгой зөрсөн: contract=%s skew=%d maxAge=%d", f.Contract, f.ClockSkewSeconds, f.MaxAgeSeconds)
	}
	l := f.Limits
	if l.MaxFields != qrMaxFields || l.MaxKeyChars != qrMaxKeyRunes || l.MaxValueBytes != qrMaxValueBytes || l.MaxPhotoBytes != qrMaxPhotoBytes {
		t.Fatalf("limits зөрсөн: %+v", l)
	}
	for _, c := range f.Parse {
		tok, err := ParseQR(c.In)
		if c.Error != "" {
			var qe *QRError
			if !errors.As(err, &qe) || qe.Code != c.Error {
				t.Errorf("parse %q: want %s, got %v", c.In, c.Error, err)
			}
			continue
		}
		if err != nil || tok != c.Token {
			t.Errorf("parse %q: %q %v", c.In, tok, err)
		}
	}
	for _, c := range f.Verify {
		t.Run(c.Name, func(t *testing.T) {
			trust := TrustConfig{
				TrustAnchorsPEM: f.Trust.AnchorsPEM, IntermediatesPEM: f.Trust.IntermediatesPEM,
				AllowedIssuerSKIs: f.Trust.AllowedIssuerSKIs, Revocation: stubRevocation(c.Revocation),
			}
			e := c.Expect
			res, err := VerifyQRPresentation(context.Background(), c.JWS, QRExpect{
				RPUUID: e.RPUUID, SessionID: e.SessionID, Nonce: e.Nonce, Issuer: orDefault(e.Issuer, f.Issuer), Now: time.Unix(e.Now, 0),
			}, trust)
			if c.Error != "" {
				var qe *QRError
				if !errors.As(err, &qe) || qe.Code != c.Error {
					t.Fatalf("want %s, got %v", c.Error, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			w := c.Result
			if w == nil {
				t.Fatal("vector-д result ч error ч алга")
			}
			var got map[string]any
			b, _ := json.Marshal(res.Claims)
			_ = json.Unmarshal(b, &got)
			for k, want := range w.Claims {
				if !reflect.DeepEqual(got[k], want) {
					t.Errorf("claims.%s = %v, want %v", k, got[k], want)
				}
			}
			if !slices.Equal(res.Keys, w.DataKeys) || !reflect.DeepEqual(res.Data, w.Data) || res.Source != w.Source {
				t.Errorf("data: keys=%v source=%s", res.Keys, res.Source)
			}
			switch {
			case w.PhotoSha256 == nil && res.Photo != nil:
				t.Error("photo байх ёсгүй")
			case w.PhotoSha256 != nil && hexSHA256(res.Photo) != *w.PhotoSha256:
				t.Error("photoSha256 зөрсөн")
			}
			if res.Signer.ETSI != w.Signer.ETSI || hexSHA256(res.Signer.Certificate.Raw) != w.Signer.CertSha256 {
				t.Errorf("signer: %s", res.Signer.ETSI)
			}
			if res.SHA256 != w.SHA256 || res.JWS != c.JWS || res.SignedAt.Unix() != res.Claims.Iat {
				t.Errorf("sha256 / jws / signedAt зөрсөн")
			}
		})
	}
}

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// TestQRVectorsFile — CA-ийн эх vector файл (байвал). Байт-ижил байхыг SHA-256-аар pin хийнэ.
func TestQRVectorsFile(t *testing.T) {
	raw, err := os.ReadFile(myqrVectorsFile)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("%s алга — CA-ийн feat/myqr-аас хуулна (гэрээ §7.1)", myqrVectorsFile)
	}
	if err != nil {
		t.Fatal(err)
	}
	if got := hexSHA256(raw); got != myqrVectorsSHA256 {
		t.Fatalf("%s SHA-256 = %s, pin (myqrVectorsSHA256) = %q — CA-ийн файлтай байт-ижил эсэхийг шалгаад pin хий", myqrVectorsFile, got, myqrVectorsSHA256)
	}
	var f myqrVectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	runQRVectors(t, &f)
}

// ── тестийн PKI (§7.1-ийн бүтэц, Go-оор үүсгэнэ) ──

const (
	mqIat    int64 = 1793000000
	mqRP           = "6f1c2a9e-1b7d-4c2e-9a51-3d8e5b7c9f01"
	mqSid          = "3f0d4a52-8e1b-4f6a-b0c7-2d9e1a5b7c33"
	mqNonce        = "order-1042"
	mqRPName       = "Demo Bank"
	mqETSI         = "PNOMN-000000000001"
)

type myqrPKI struct {
	root, ca, otherRoot                           *testCA
	sign, auth, revoked, expired, other, rootLeaf *testCA
}

var (
	myqrPKIOnce sync.Once
	myqrPKIVal  myqrPKI
)

func mqTime(d time.Duration) time.Time { return time.Unix(mqIat, 0).Add(d) }

func mqCA(t *testing.T, cn string, parent *testCA, k *rsa.PrivateKey) *testCA {
	tmpl := profileCA(cn, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, -1)
	tmpl.NotBefore, tmpl.NotAfter = mqTime(-30*24*time.Hour), mqTime(10*365*24*time.Hour)
	return mkCert(t, tmpl, parent, &k.PublicKey, k)
}

// mqLeaf — P-CITIZEN-SIGN (sign) / P-CITIZEN-AUTH профайл, subject C=MN, SN=DORJ, GN=BAT, serialNumber=PNOMN-000000000001.
func mqLeaf(t *testing.T, issuer *testCA, sign bool, k *rsa.PrivateKey, nb, na time.Time) *testCA {
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			Country: []string{"MN"}, CommonName: "DORJ BAT", SerialNumber: mqETSI,
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "DORJ"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "BAT"},
			},
		},
		NotBefore: nb, NotAfter: na, BasicConstraintsValid: true,
		OCSPServer: []string{"http://ocsp.example.test/ocsp"},
	}
	if sign {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		tmpl.ExtraExtensions = []pkix.Extension{qcStatementsExt(false)}
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
	}
	return mkCert(t, tmpl, issuer, &k.PublicKey, k)
}

func testQRPKI(t *testing.T) myqrPKI {
	myqrPKIOnce.Do(func() {
		var p myqrPKI
		p.root = mqCA(t, "Test National Root CA", nil, newKey(t))
		p.ca = mqCA(t, "Test eID Issuing CA", p.root, newKey(t))
		p.otherRoot = mqCA(t, "Other Root CA", nil, newKey(t))
		valid := func() (time.Time, time.Time) { return mqTime(-24 * time.Hour), mqTime(365 * 24 * time.Hour) }
		nb, na := valid()
		p.sign = mqLeaf(t, p.ca, true, newKey(t), nb, na)
		p.auth = mqLeaf(t, p.ca, false, newKey(t), nb, na)
		p.revoked = mqLeaf(t, p.ca, true, newKey(t), nb, na)
		p.expired = mqLeaf(t, p.ca, true, newKey(t), mqTime(-60*24*time.Hour), mqTime(-24*time.Hour))
		p.other = mqLeaf(t, p.otherRoot, true, newKey(t), nb, na)
		p.rootLeaf = mqLeaf(t, p.root, true, newKey(t), nb, na)
		myqrPKIVal = p
	})
	return myqrPKIVal
}

func (p myqrPKI) trust(rev RevocationChecker) TrustConfig {
	return TrustConfig{
		TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: []string{p.ca.pem},
		AllowedIssuerSKIs: []string{hex.EncodeToString(p.ca.cert.SubjectKeyId)}, Revocation: rev,
	}
}

// ── CA-ийн composer-ийн хуулбар (§1.4: encoding/json, struct-ийн дараалал, fields = map → эрэмбэлэгдсэн) ──

type mqHeader struct {
	Alg string   `json:"alg"`
	Typ string   `json:"typ"`
	X5c []string `json:"x5c"`
}

type mqData struct {
	Source string            `json:"source"`
	Fields map[string]string `json:"fields"`
	Photo  string            `json:"photo,omitempty"`
}

type mqPayload struct {
	Iss       string `json:"iss"`
	Sub       string `json:"sub"`
	Aud       string `json:"aud"`
	RPName    string `json:"rp_name"`
	Sid       string `json:"sid"`
	Nonce     string `json:"nonce"`
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
	Statement string `json:"statement"`
	Data      any    `json:"data"`
}

func mqStatement(rp string) string {
	return "Та " + rp + "-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг хуваалцах гэж байна"
}

func mqFields() map[string]string {
	return map[string]string{"reg_no": "УБ90010112", "given_name": "Бат", "surname": "Дорж", "birth_date": "1990-01-01"}
}

func mqPay() *mqPayload {
	return &mqPayload{
		Iss: DefaultQRIssuer, Sub: mqETSI, Aud: mqRP, RPName: mqRPName, Sid: mqSid, Nonce: mqNonce,
		Iat: mqIat, Exp: mqIat + 300, Statement: mqStatement(mqRPName), Data: &mqData{Source: "citizenid", Fields: mqFields()},
	}
}

func x5cOf(cs ...*testCA) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = base64.StdEncoding.EncodeToString(c.cert.Raw)
	}
	return out
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mqSign — compact JWS; pkcs1 бол (буруу) RS256 гарын үсэг.
func mqSign(t *testing.T, key crypto.Signer, hdr any, payload []byte, pkcs1 bool) string {
	t.Helper()
	hb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	in := b64u(hb) + "." + b64u(payload)
	h := sha256.Sum256([]byte(in))
	k := key.(*rsa.PrivateKey)
	var sig []byte
	if pkcs1 {
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	} else {
		sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: 32})
	}
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64u(sig)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jpegBytes(n int) []byte {
	b := bytes.Repeat([]byte{0x42}, n)
	copy(b, []byte{0xFF, 0xD8, 0xFF, 0xE0})
	return b
}

type mqCase struct {
	name   string
	leaf   *testCA           // x5c[0] + гарын үсэг (nil = sign)
	hdr    any               // nil = PS256 header [leaf, ca]
	pay    *mqPayload        // nil = mqPay()
	rawPay []byte            // payload-ийн байт (pay-г дарна)
	jws    string            // бүтэн JWS (бусдыг дарна)
	now    int64             // 0 = iat + 10
	rp     string            // expect.rpUUID ("" = mqRP)
	rev    map[string]string // nil = {leaf: good}
	pkcs1  bool
	tamper bool
	err    string
	check  func(t *testing.T, payload []byte)
}

// buildQRVectors — §7.2 форматын vector-уудыг тестийн PKI-аар үүсгэнэ (§7.2-ийн заавал нэрс). Хүлээгдэх үр дүнг
// verifier-ээс биш, оролтоос тооцно.
func buildQRVectors(t *testing.T) *myqrVectorFile {
	p := testQRPKI(t)
	f := &myqrVectorFile{Contract: myqrContractID, Issuer: DefaultQRIssuer, ClockSkewSeconds: 60, MaxAgeSeconds: 300}
	f.Limits.MaxFields, f.Limits.MaxKeyChars, f.Limits.MaxValueBytes, f.Limits.MaxPhotoBytes = 128, 64, 2048, 153600
	f.Trust.AnchorsPEM = []string{p.root.pem}
	f.Trust.IntermediatesPEM = []string{p.ca.pem}
	f.Trust.AllowedIssuerSKIs = []string{hex.EncodeToString(p.ca.cert.SubjectKeyId)}
	tok := "Qm9yamlnaW4tdGVzdC10b2tlbi0wMDAwMDAwMDAwMDA"
	for _, x := range []struct{ in, token, err string }{
		{QRPrefix + tok, tok, ""}, {"  EIDMN-QR1:" + tok + "\n", tok, ""}, {"EIDMN-QR2:" + tok, "", CodeQRFormatInvalid},
		{tok, "", CodeQRFormatInvalid}, {QRPrefix + tok[:42], "", CodeQRFormatInvalid}, {QRPrefix + tok + "=", "", CodeQRFormatInvalid},
	} {
		f.Parse = append(f.Parse, struct {
			In    string `json:"in"`
			Token string `json:"token,omitempty"`
			Error string `json:"error,omitempty"`
		}{x.in, x.token, x.err})
	}

	pay := func(mut func(*mqPayload)) *mqPayload { x := mqPay(); mut(x); return x }
	data := func(mut func(*mqData)) *mqPayload {
		return pay(func(x *mqPayload) { d := x.Data.(*mqData); mut(d) })
	}
	raw := func(s string) *mqPayload { return pay(func(x *mqPayload) { x.Data = json.RawMessage(s) }) }
	hdr := func(mut func(*mqHeader)) *mqHeader {
		h := &mqHeader{Alg: "PS256", Typ: QRJWSType, X5c: x5cOf(p.sign, p.ca)}
		mut(h)
		return h
	}
	many := map[string]string{}
	for i := range 129 {
		many[fmt.Sprintf("k%03d", i)] = "v"
	}
	photo := base64.StdEncoding.EncodeToString(jpegBytes(2048))
	other := "11111111-2222-3333-4444-555555555555"

	cases := []mqCase{
		{name: "ok_basic"},
		{name: "ok_photo", pay: data(func(d *mqData) { d.Photo = photo })},
		{name: "ok_unicode", pay: data(func(d *mqData) {
			d.Fields = map[string]string{"нэр": "Бат-Эрдэнэ 🙂", "note": "<b>&amp;</b>", "эмодзи🎉": "", "a\"q": "x\\y"}
		}), check: func(t *testing.T, pb []byte) {
			if !bytes.Contains(pb, []byte("\\u003cb\\u003e\\u0026amp;\\u003c/b\\u003e")) || !bytes.Contains(pb, []byte("🙂")) {
				t.Fatalf("ok_unicode payload нь Go encoding/json-ийн escaping-гүй: %s", pb)
			}
		}},
		{name: "ok_aud_uppercase_expect", rp: strings.ToUpper(mqRP)},
		{name: "ok_skew_edge", now: mqIat + 300 + 59},
		{name: "ok_source_unknown", pay: data(func(d *mqData) { d.Source = "unknown" })},
		{name: "malformed_segments", jws: "eyJhbGciOiJQUzI1NiJ9.e30", err: CodeQRJWSMalformed},
		{name: "header_extra_kid", hdr: map[string]any{"alg": "PS256", "typ": QRJWSType, "x5c": x5cOf(p.sign, p.ca), "kid": "k1"}, err: CodeQRHeaderInvalid},
		{name: "header_alg_rs256", hdr: hdr(func(h *mqHeader) { h.Alg = "RS256" }), pkcs1: true, err: CodeQRHeaderInvalid},
		{name: "header_alg_none", hdr: hdr(func(h *mqHeader) { h.Alg = "none" }), err: CodeQRHeaderInvalid},
		{name: "header_typ_jwt", hdr: hdr(func(h *mqHeader) { h.Typ = "JWT" }), err: CodeQRHeaderInvalid},
		{name: "x5c_single", hdr: hdr(func(h *mqHeader) { h.X5c = h.X5c[:1] }), err: CodeQRHeaderInvalid},
		{name: "x5c_garbage", hdr: hdr(func(h *mqHeader) { h.X5c[1] = base64.StdEncoding.EncodeToString([]byte("not a certificate")) }), err: CodeQRHeaderInvalid},
		{name: "chain_other_root", leaf: p.other, hdr: &mqHeader{Alg: "PS256", Typ: QRJWSType, X5c: x5cOf(p.other, p.otherRoot)}, err: CodeQRChainInvalid},
		{name: "chain_issuer_not_allowed", leaf: p.rootLeaf, hdr: &mqHeader{Alg: "PS256", Typ: QRJWSType, X5c: x5cOf(p.rootLeaf, p.root)}, err: CodeQRChainInvalid},
		{name: "leaf_auth_profile", leaf: p.auth, err: CodeQRChainInvalid},
		{name: "leaf_expired", leaf: p.expired, err: CodeQRChainInvalid},
		{name: "leaf_revoked", leaf: p.revoked, rev: map[string]string{p.revoked.cert.SerialNumber.Text(16): "revoked"}, err: CodeQRCertRevoked},
		{name: "revocation_unknown", rev: map[string]string{}, err: CodeQRRevocationUnknown},
		{name: "bad_signature", tamper: true, err: CodeQRSignatureInvalid},
		{name: "signature_pkcs1v15", pkcs1: true, err: CodeQRSignatureInvalid},
		{name: "payload_not_json", rawPay: []byte("not json"), err: CodeQRJWSMalformed},
		{name: "iss_wrong", pay: pay(func(x *mqPayload) { x.Iss = "https://ca.example.test" }), err: CodeQRClaimsInvalid},
		{name: "sub_mismatch_cert", pay: pay(func(x *mqPayload) { x.Sub = "PNOMN-000000000002" }), err: CodeQRClaimsInvalid},
		{name: "statement_wrong_rp", pay: pay(func(x *mqPayload) { x.Statement = mqStatement("Other Bank") }), err: CodeQRClaimsInvalid},
		{name: "aud_mismatch", pay: pay(func(x *mqPayload) { x.Aud = other }), err: CodeQRAudienceMismatch},
		{name: "sid_mismatch", pay: pay(func(x *mqPayload) { x.Sid = other }), err: CodeQRSessionMismatch},
		{name: "nonce_mismatch", pay: pay(func(x *mqPayload) { x.Nonce = "order-1043" }), err: CodeQRNonceMismatch},
		{name: "exp_minus_iat_301", pay: pay(func(x *mqPayload) { x.Exp = x.Iat + 301 }), err: CodeQRClaimsInvalid},
		{name: "iat_future", now: mqIat - 61, err: CodeQRNotYetValid},
		{name: "expired", now: mqIat + 300 + 61, err: CodeQRExpired},
		{name: "data_value_number", pay: raw(`{"source":"citizenid","fields":{"reg_no":"УБ90010112","age":30}}`), err: CodeQRDataInvalid},
		{name: "data_value_too_long", pay: data(func(d *mqData) { d.Fields["long"] = strings.Repeat("a", 2049) }), err: CodeQRDataInvalid},
		{name: "data_key_too_long", pay: data(func(d *mqData) { d.Fields[strings.Repeat("к", 65)] = "x" }), err: CodeQRDataInvalid},
		{name: "data_too_many_fields", pay: data(func(d *mqData) { d.Fields = many }), err: CodeQRDataInvalid},
		{name: "photo_not_jpeg", pay: data(func(d *mqData) {
			d.Photo = base64.StdEncoding.EncodeToString(append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, make([]byte, 64)...))
		}), err: CodeQRDataInvalid},
		{name: "photo_too_large", pay: data(func(d *mqData) { d.Photo = base64.StdEncoding.EncodeToString(jpegBytes(153601)) }), err: CodeQRDataInvalid},
		{name: "data_extra_member", pay: raw(`{"source":"citizenid","fields":{"reg_no":"УБ90010112"},"scan":"AAAA"}`), err: CodeQRDataInvalid},
	}
	for _, c := range cases {
		leaf := c.leaf
		if leaf == nil {
			leaf = p.sign
		}
		h := c.hdr
		if h == nil {
			h = &mqHeader{Alg: "PS256", Typ: QRJWSType, X5c: x5cOf(leaf, p.ca)}
		}
		pl := c.pay
		if pl == nil {
			pl = mqPay()
		}
		pb := c.rawPay
		if pb == nil {
			pb = mustJSON(t, pl)
		}
		if c.check != nil {
			c.check(t, pb)
		}
		jws := c.jws
		if jws == "" {
			jws = mqSign(t, leaf.key, h, pb, c.pkcs1)
		}
		if c.tamper {
			i := strings.LastIndexByte(jws, '.')
			sig, _ := base64.RawURLEncoding.DecodeString(jws[i+1:])
			sig[10] ^= 0x01
			jws = jws[:i+1] + b64u(sig)
		}
		v := myqrVerifyVector{Name: c.name, JWS: jws, Error: c.err, Revocation: c.rev}
		if v.Revocation == nil {
			v.Revocation = map[string]string{leaf.cert.SerialNumber.Text(16): "good"}
		}
		v.Expect.RPUUID, v.Expect.SessionID, v.Expect.Nonce, v.Expect.Now = orDefault(c.rp, mqRP), mqSid, mqNonce, c.now
		if v.Expect.Now == 0 {
			v.Expect.Now = mqIat + 10
		}
		if c.err == "" {
			d := pl.Data.(*mqData)
			keys := make([]string, 0, len(d.Fields))
			for k := range d.Fields {
				keys = append(keys, k)
			}
			sort.Strings(keys) // CA: map[string]string → байтын дараалал
			v.Result = &struct {
				Claims      map[string]any    `json:"claims"`
				DataKeys    []string          `json:"dataKeys"`
				Data        map[string]string `json:"data"`
				Source      string            `json:"source"`
				PhotoSha256 *string           `json:"photoSha256"`
				Signer      struct {
					ETSI       string `json:"etsi"`
					CertSha256 string `json:"certSha256"`
				} `json:"signer"`
				SHA256 string `json:"sha256"`
			}{DataKeys: keys, Data: d.Fields, Source: d.Source}
			_ = json.Unmarshal(pb, &v.Result.Claims)
			if d.Photo != "" {
				ph, _ := base64.StdEncoding.DecodeString(d.Photo)
				s := hexSHA256(ph)
				v.Result.PhotoSha256 = &s
			}
			v.Result.Signer.ETSI, v.Result.Signer.CertSha256 = mqETSI, hexSHA256(leaf.cert.Raw)
			v.Result.SHA256 = hexSHA256([]byte(jws[:strings.LastIndexByte(jws, '.')]))
		}
		f.Verify = append(f.Verify, v)
	}
	return f
}

// TestQRVectors — §7.2 форматын vector-ууд (локал PKI) + JSON-оор дамжуулсны дараа ч ижил (файлын runner-тэй нэг код).
func TestQRVectors(t *testing.T) {
	f := buildQRVectors(t)
	b := mustJSON(t, f)
	var back myqrVectorFile
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	runQRVectors(t, &back)
}

// ── VerifyQRPresentation-ийн итгэлийн тохиргоо ──

func mqJWS(t *testing.T, leaf *testCA, pl *mqPayload) string {
	p := testQRPKI(t)
	return mqSign(t, leaf.key, &mqHeader{Alg: "PS256", Typ: QRJWSType, X5c: x5cOf(leaf, p.ca)}, mustJSON(t, pl), false)
}

func mqExpect() QRExpect {
	return QRExpect{RPUUID: mqRP, SessionID: mqSid, Nonce: mqNonce, Now: time.Unix(mqIat+10, 0)}
}

func wantQRCode(t *testing.T, err error, code string) {
	t.Helper()
	var qe *QRError
	if !errors.As(err, &qe) || qe.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestQRVerifyTrust(t *testing.T) {
	p := testQRPKI(t)
	ctx := context.Background()
	jws := mqJWS(t, p.sign, mqPay())

	// x5c[1] нь завсрын CA-г дангаараа хангана (IntermediatesPEM хоосон); checker шууд issuer-ийг авна.
	tr := p.trust(func(_ context.Context, cert, issuer *x509.Certificate) (RevocationStatus, error) {
		if issuer == nil || !issuer.Equal(p.ca.cert) {
			t.Error("revocation checker-т issuer буруу")
		}
		return RevocationGood, nil
	})
	tr.IntermediatesPEM = []string{}
	res, err := VerifyQRPresentation(ctx, jws, mqExpect(), tr)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signer.GivenName != "BAT" || res.Signer.Surname != "DORJ" || res.Signer.ETSI != mqETSI || res.Photo != nil ||
		!slices.Equal(res.Keys, []string{"birth_date", "given_name", "reg_no", "surname"}) || res.Data["reg_no"] != "УБ90010112" {
		t.Fatalf("%+v", res)
	}

	// unknown / алдаа: hard-fail (анхдагч) → QR_REVOCATION_UNKNOWN (Cause хадгална); soft-fail → зөвшөөрнө.
	boom := errors.New("ocsp down")
	errChecker := func(context.Context, *x509.Certificate, *x509.Certificate) (RevocationStatus, error) { return "", boom }
	_, err = VerifyQRPresentation(ctx, jws, mqExpect(), p.trust(errChecker))
	wantQRCode(t, err, CodeQRRevocationUnknown)
	if !errors.Is(err, boom) || !errors.Is(err, ErrQRRevocationUnknown) {
		t.Fatal("cause / sentinel", err)
	}
	soft := p.trust(errChecker)
	soft.RevocationMode = RevocationSoftFail
	if _, err := VerifyQRPresentation(ctx, jws, mqExpect(), soft); err != nil {
		t.Fatal("soft-fail", err)
	}
	soft.Revocation = stubRevocation(map[string]string{p.sign.cert.SerialNumber.Text(16): "revoked"})
	_, err = VerifyQRPresentation(ctx, jws, mqExpect(), soft)
	wantQRCode(t, err, CodeQRCertRevoked)

	// Anchor өгөөгүй → SDK-ийн NationalRootCAPEM (тестийн PKI итгэгдэхгүй); AllowUntrusted энд үйлчлэхгүй.
	_, err = VerifyQRPresentation(ctx, jws, mqExpect(), TrustConfig{AllowUntrusted: true, Revocation: stubRevocation(nil)})
	wantQRCode(t, err, CodeQRChainInvalid)
	// Анхдагч issuer allowlist = CitizenIssuingCASKI.
	noSKI := p.trust(stubRevocation(nil))
	noSKI.AllowedIssuerSKIs = nil
	_, err = VerifyQRPresentation(ctx, jws, mqExpect(), noSKI)
	wantQRCode(t, err, CodeQRChainInvalid)

	// Expect хоосон бол fail-closed.
	for _, e := range []QRExpect{{SessionID: mqSid, Nonce: mqNonce}, {RPUUID: mqRP, Nonce: mqNonce}, {RPUUID: mqRP, SessionID: mqSid}} {
		e.Now = time.Unix(mqIat+10, 0)
		if _, err := VerifyQRPresentation(ctx, jws, e, p.trust(stubRevocation(map[string]string{p.sign.cert.SerialNumber.Text(16): "good"}))); err == nil {
			t.Fatal("хоосон expect зөвшөөрөгдөв", e)
		}
	}
}

func TestQRVerifyStrictJSON(t *testing.T) {
	p := testQRPKI(t)
	ctx := context.Background()
	good := p.trust(stubRevocation(map[string]string{p.sign.cert.SerialNumber.Text(16): "good"}))
	x5c, _ := json.Marshal(x5cOf(p.sign, p.ca))
	sign := func(hdr json.RawMessage, pb []byte) string { return mqSign(t, p.sign.key, hdr, pb, false) }
	pl := mustJSON(t, mqPay())

	// Давхардсан header түлхүүр.
	_, err := VerifyQRPresentation(ctx, sign(json.RawMessage(`{"alg":"PS256","typ":"`+QRJWSType+`","alg":"PS256","x5c":`+string(x5c)+`}`), pl), mqExpect(), good)
	wantQRCode(t, err, CodeQRHeaderInvalid)
	hdr := json.RawMessage(`{"alg":"PS256","typ":"` + QRJWSType + `","x5c":` + string(x5c) + `}`)
	// Давхардсан fields түлхүүр, payload-ийн дараах илүү өгөгдөл.
	dup := bytes.Replace(pl, []byte(`"birth_date":"1990-01-01"`), []byte(`"birth_date":"1990-01-01","birth_date":"2000-01-01"`), 1)
	_, err = VerifyQRPresentation(ctx, sign(hdr, dup), mqExpect(), good)
	wantQRCode(t, err, CodeQRDataInvalid)
	_, err = VerifyQRPresentation(ctx, sign(hdr, append(append([]byte{}, pl...), []byte(` {}`)...)), mqExpect(), good)
	wantQRCode(t, err, CodeQRJWSMalformed)
	// x5c-д мөр таслалтай base64 (Go-ийн decoder CR/LF алгасдаг) → татгалзана.
	nl := json.RawMessage(`{"alg":"PS256","typ":"` + QRJWSType + `","x5c":["` + x5cOf(p.sign)[0][:40] + `\n` + x5cOf(p.sign)[0][40:] + `","` + x5cOf(p.ca)[0] + `"]}`)
	_, err = VerifyQRPresentation(ctx, sign(nl, pl), mqExpect(), good)
	wantQRCode(t, err, CodeQRHeaderInvalid)

	// fields хоосон + photo → зөвшөөрнө; хоосон + photo-гүй → QR_DATA_INVALID.
	withPhoto := mqPay()
	withPhoto.Data = &mqData{Source: "dan", Fields: map[string]string{}, Photo: base64.StdEncoding.EncodeToString(jpegBytes(16))}
	res, err := VerifyQRPresentation(ctx, mqJWS(t, p.sign, withPhoto), mqExpect(), good)
	if err != nil || len(res.Keys) != 0 || len(res.Photo) != 16 || res.Claims.Data.Photo == "" {
		t.Fatal("хоосон fields + photo", err)
	}
	empty := mqPay()
	empty.Data = &mqData{Source: "dan", Fields: map[string]string{}}
	_, err = VerifyQRPresentation(ctx, mqJWS(t, p.sign, empty), mqExpect(), good)
	wantQRCode(t, err, CodeQRDataInvalid)
}

// ── mock RP-API ──

type qrStub struct {
	t         *testing.T
	srv       *httptest.Server
	startReq  map[string]any
	startHits int
	state     string
	end       string
	gone      bool
	mutate    func(*mqPayload)
}

const (
	mqTokOK      = "q9Xk3vQh2m9cTqL8rW1xYb5nPdA0sE6uJgHtKoVfRiM"
	mqTokNoCert  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	mqTokInvalid = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	mqTokDenied  = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
)

func newQRStub(t *testing.T) (*qrStub, *Client) {
	t.Helper()
	p := testQRPKI(t)
	s := &qrStub{t: t, state: "COMPLETE", end: "OK"}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fail := func(status int, code string) {
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"error":"алдаа","code":%q}`, code)
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/authentication/qr":
			if r.Header.Get("Authorization") != "Bearer "+creds.APISecret {
				t.Error("Bearer алга")
			}
			s.startHits++
			s.startReq = nil
			_ = json.NewDecoder(r.Body).Decode(&s.startReq)
			switch strings.TrimPrefix(s.startReq["qr"].(string), QRPrefix) {
			case mqTokNoCert:
				fail(409, CodeNoSigningCertificate)
			case mqTokInvalid:
				fail(404, CodeQRTokenInvalid)
			case mqTokDenied:
				fail(403, "PERMISSION_DENIED")
			default:
				_, _ = w.Write([]byte(`{"sessionID":"sid-1"}`))
			}
		case r.Method == "GET" && r.URL.Path == "/session/sid-1":
			if s.gone {
				fail(410, CodeQRPresentationGone)
				return
			}
			body := map[string]any{"state": s.state}
			if s.state == "COMPLETE" {
				body["result"] = map[string]any{"endResult": s.end}
			}
			if s.state == "COMPLETE" && s.end == "OK" {
				now := time.Now().Unix()
				pl := mqPay()
				pl.Aud, pl.Sid, pl.Iat, pl.Exp = creds.RPUUID, "sid-1", now, now+300
				pl.Nonce, _ = s.startReq["nonce"].(string)
				pl.Data = &mqData{Source: "dan", Fields: mqFields(), Photo: base64.StdEncoding.EncodeToString(jpegBytes(64))}
				if s.mutate != nil {
					s.mutate(pl)
				}
				body["signatureProtocol"] = "RAW_DIGEST_SIGNATURE"
				body["presentation"] = map[string]any{"v": 2, "jws": mqJWS(t, p.sign, pl)}
			}
			_ = json.NewEncoder(w).Encode(body)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.srv.Close)
	c, err := NewClient(Config{BaseURL: s.srv.URL, Credentials: creds,
		Trust: p.trust(stubRevocation(map[string]string{p.sign.cert.SerialNumber.Text(16): "good"}))})
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func TestQRStartResult(t *testing.T) {
	s, c := newQRStub(t)
	ctx := context.Background()
	sess, err := c.QR.Start(ctx, QRStartRequest{QR: " " + QRPrefix + mqTokOK + "\n"})
	if err != nil {
		t.Fatal(err)
	}
	r := s.startReq
	if sess.SessionID != "sid-1" || len(sess.Nonce) != 22 || r["nonce"] != sess.Nonce || r["qr"] != QRPrefix+mqTokOK ||
		r["relyingPartyUUID"] != creds.RPUUID || r["relyingPartyName"] != creds.RPName || len(r) != 4 {
		t.Fatalf("sess=%+v body=%v", sess, r)
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(sess.Nonce); err != nil {
		t.Fatal("nonce base64url биш", err)
	}
	// QRSession JSON-оор хадгалагдаж дахин уншигдана (stateless RP).
	var back QRSession
	_ = json.Unmarshal(mustJSON(t, sess), &back)
	res, err := c.QR.Result(ctx, &back, &WaitOptions{MaxWait: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	in := res.JWS[:strings.LastIndexByte(res.JWS, '.')]
	if res.Source != "dan" || len(res.Photo) != 64 || res.SHA256 != hexSHA256([]byte(in)) || res.Signer.ETSI != mqETSI ||
		!slices.Equal(res.Keys, []string{"birth_date", "given_name", "reg_no", "surname"}) || res.Claims.Nonce != sess.Nonce {
		t.Fatalf("%+v", res)
	}
	// Өөрийн nonce / дэд системийн нэр.
	sess, err = c.QR.Start(ctx, QRStartRequest{QR: QRPrefix + mqTokOK, Nonce: "order-1042-xyz-0001", RelyingPartyName: "Касс 3"})
	if err != nil || sess.Nonce != "order-1042-xyz-0001" || s.startReq["relyingPartyName"] != "Касс 3" {
		t.Fatal(sess, err)
	}
	if chk, err := c.QR.Check(ctx, sess, 0); err != nil || !chk.Complete || chk.Presentation.Claims.Nonce != "order-1042-xyz-0001" {
		t.Fatal("check", chk, err)
	}
}

func TestQRStartErrors(t *testing.T) {
	s, c := newQRStub(t)
	ctx := context.Background()
	// Буруу хэлбэр → QR_FORMAT_INVALID клиент талд, сүлжээгүй.
	var err error
	for _, q := range []string{mqTokOK, "hello", QRPrefix + "short", "EIDMN-QR2:" + mqTokOK} {
		_, err = c.QR.Start(ctx, QRStartRequest{QR: q})
		wantQRCode(t, err, CodeQRFormatInvalid)
		if !errors.Is(err, ErrQRFormatInvalid) {
			t.Fatal("sentinel", err)
		}
	}
	if s.startHits != 0 {
		t.Fatal("клиент талын алдаа CA руу явсан")
	}
	var ae *APIError
	// 409 NO_SIGNING_CERTIFICATE — хэвээр *APIError.
	_, err = c.QR.Start(ctx, QRStartRequest{QR: QRPrefix + mqTokNoCert})
	if !errors.Is(err, ErrNoSigningCertificate) || !errors.As(err, &ae) || ae.Status != 409 {
		t.Fatal("409", err)
	}
	// 404 QR_TOKEN_INVALID.
	_, err = c.QR.Start(ctx, QRStartRequest{QR: QRPrefix + mqTokInvalid})
	wantQRCode(t, err, CodeQRTokenInvalid)
	if !errors.Is(err, ErrQRTokenInvalid) || !errors.As(err, &ae) || ae.Status != 404 {
		t.Fatal("404", err)
	}
	// 403 PERMISSION_DENIED — хэвээр *ForbiddenError.
	_, err = c.QR.Start(ctx, QRStartRequest{QR: QRPrefix + mqTokDenied})
	var fe *ForbiddenError
	if !errors.As(err, &fe) || fe.Code != "PERMISSION_DENIED" {
		t.Fatal("403", err)
	}
}

func TestQRResultFailures(t *testing.T) {
	s, c := newQRStub(t)
	ctx := context.Background()
	sess, err := c.QR.Start(ctx, QRStartRequest{QR: QRPrefix + mqTokOK})
	if err != nil {
		t.Fatal(err)
	}
	wo := &WaitOptions{MaxWait: 2 * time.Second, ServerPoll: time.Second}
	var sf *SessionFailedError

	s.end = "USER_REFUSED"
	if _, err := c.QR.Result(ctx, sess, wo); !errors.As(err, &sf) || sf.EndResult != "USER_REFUSED" {
		t.Fatal("refused", err)
	}
	if _, err := c.QR.Check(ctx, sess, 0); !errors.As(err, &sf) || sf.EndResult != "USER_REFUSED" {
		t.Fatal("check refused", err)
	}
	s.end = "OK"

	// 410 → QR_PRESENTATION_GONE.
	s.gone = true
	_, err = c.QR.Result(ctx, sess, wo)
	wantQRCode(t, err, CodeQRPresentationGone)
	var ae *APIError
	if !errors.Is(err, ErrQRPresentationGone) || !errors.As(err, &ae) || ae.Status != 410 {
		t.Fatal("410", err)
	}
	_, err = c.QR.Check(ctx, sess, 0)
	wantQRCode(t, err, CodeQRPresentationGone)
	s.gone = false

	// RUNNING.
	s.state = "RUNNING"
	if _, err := c.QR.Result(ctx, sess, &WaitOptions{MaxWait: time.Second, ServerPoll: time.Second}); !errors.Is(err, ErrQRPending) {
		t.Fatal("pending", err)
	}
	if chk, err := c.QR.Check(ctx, sess, 0); err != nil || chk.Complete || chk.Presentation != nil {
		t.Fatal("check running", chk, err)
	}
	s.state = "COMPLETE"

	// Шалгалтад унавал *QRError — ИТГЭХГҮЙ.
	s.mutate = func(p *mqPayload) { p.Aud = "other-rp" }
	_, err = c.QR.Result(ctx, sess, wo)
	wantQRCode(t, err, CodeQRAudienceMismatch)
	sess2 := *sess
	sess2.Nonce = "replayed-nonce-0000"
	s.mutate = nil
	_, err = c.QR.Check(ctx, &sess2, 0)
	wantQRCode(t, err, CodeQRNonceMismatch)
}
