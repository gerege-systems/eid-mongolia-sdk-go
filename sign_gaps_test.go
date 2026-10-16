package eid

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

const dlReply = `{"sessionID":"0b8f3f0e-1111-4222-8333-444455556666","sessionToken":"tok_abc-123",` +
	`"sessionSecret":"c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTMyYg==","deviceLinkBase":"https://ca.eidmongolia.mn/dl","vc":"12345"}`

func bodyMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func keys(m map[string]any) string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return strings.Join(k, ",")
}

func TestSignDeviceLink(t *testing.T) {
	c, rc := server(t, jsonReply(200, dlReply))
	ctx := context.Background()
	digest := SHA256Base64([]byte("гэрээ"))
	ix := []Interaction{{Type: "displayTextAndPIN", DisplayText60: "Гэрээнд гарын үсэг зурах"}}
	before := time.Now()
	s, err := c.Sign.DeviceLinkByEtsi(ctx, "PNOMN-12345678", digest, ix, &SignOptions{
		CallbackURL: " https://rp.example.mn/cb ", FileName: "Гэрээ.pdf", OnBehalfOf: "NTRMN-6235972",
		SignatureAlgorithm: AlgSHA256WithRSA,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, body := rc.last()
	if req.Method != "POST" || req.URL.Path != "/signature/device-link/etsi/PNOMN-12345678" {
		t.Fatal(req.Method, req.URL.Path)
	}
	m := bodyMap(t, body)
	if m["initialCallbackUrl"] != "https://rp.example.mn/cb" || m["fileName"] != "Гэрээ.pdf" || m["onBehalfOf"] != "NTRMN-6235972" ||
		m["signatureProtocol"] != "RAW_DIGEST_SIGNATURE" || m["interactions"] != s.Sign.Interactions {
		t.Fatal(m)
	}
	spp := m["signatureProtocolParameters"].(map[string]any)
	if spp["digest"] != digest || spp["signatureAlgorithm"] != "sha256WithRSAEncryption" ||
		spp["signatureAlgorithmParameters"].(map[string]any)["hashAlgorithm"] != "SHA-256" {
		t.Fatal(spp)
	}
	if s.SessionID == "" || s.SessionToken != "tok_abc-123" || s.VC != "12345" || s.SessionType != SessionSign ||
		s.Sign.Digest != digest || s.Sign.RelyingPartyName != creds.RPName || s.Sign.InitialCallbackURL != "https://rp.example.mn/cb" {
		t.Fatalf("%+v", s)
	}
	if s.ExpiresAt.Before(before.Add(DefaultSignSessionTTL)) || s.ExpiresAt.After(time.Now().Add(DefaultSignSessionTTL)) {
		t.Fatal("ExpiresAt", s.ExpiresAt)
	}
	for _, typ := range []DeviceLinkType{LinkQR, LinkWeb2App, LinkApp2App} {
		l, err := BuildDeviceLink(s.LinkInput(typ, "mon"))
		if err != nil || !strings.Contains(l, "sessionType=sign") || !strings.Contains(l, "deviceLinkType="+string(typ)) {
			t.Fatal(typ, l, err)
		}
	}
	// LinkInput нь гараар угсарсантай байт-ижил (Web2App — callback authCode-д ордог).
	manual, _ := BuildDeviceLink(DeviceLinkInput{
		DeviceLinkBase: s.DeviceLinkBase, DeviceLinkType: LinkWeb2App, SessionToken: s.SessionToken, SessionSecret: s.SessionSecret,
		SessionType: SessionSign, Lang: "mon", Digest: digest, RelyingPartyName: creds.RPName, Interactions: s.Sign.Interactions,
		InitialCallbackURL: "https://rp.example.mn/cb",
	})
	if got, _ := BuildDeviceLink(s.LinkInput(LinkWeb2App, "mon")); got != manual {
		t.Fatal(got, manual)
	}

	if _, err := c.Sign.DeviceLinkByDocument(ctx, "PNOMN-12345678-MOCK-Q", digest, ix, nil); err != nil {
		t.Fatal(err)
	}
	req, body = rc.last()
	if req.URL.Path != "/signature/device-link/document/PNOMN-12345678-MOCK-Q" {
		t.Fatal(req.URL.Path)
	}
	m = bodyMap(t, body)
	if _, ok := m["initialCallbackUrl"]; ok {
		t.Fatal("callback-гүй session-д initialCallbackUrl илгээгдэв")
	}
	if m["signatureProtocolParameters"].(map[string]any)["signatureAlgorithm"] != "rsassa-pss" {
		t.Fatal("DeviceLinkByDocument-ийн анхдагч rsassa-pss хэвээр байх ёстой", m)
	}
}

func TestSignExpiresAt(t *testing.T) {
	srvC, _ := server(t, jsonReply(200, `{"sessionID":"s1","vc":{"type":"alphaNumeric5","value":"54321"}}`))
	s, err := srvC.Sign.DigestByEtsi(context.Background(), "PNOMN-1", SHA256Base64(nil), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(s.ExpiresAt); d < DefaultSignSessionTTL-5*time.Second || d > DefaultSignSessionTTL {
		t.Fatal(d)
	}
	if s.Sign == nil || s.Sign.SignatureAlgorithm != AlgRSASSAPSS {
		t.Fatalf("%+v", s.Sign)
	}
	if got := SessionExpiry(time.Unix(0, 0), 0); !got.Equal(time.Unix(0, 0).Add(600 * time.Second)) {
		t.Fatal(got)
	}
	// Config.SignSessionTTL — CA-ийн админ тохиргоог дагана.
	c2, err := NewClient(Config{BaseURL: "http://127.0.0.1:1", Credentials: creds, Trust: TrustConfig{AllowUntrusted: true}, SignSessionTTL: 90 * time.Second})
	if err != nil || c2.Sign.ttl != 90*time.Second {
		t.Fatal(err)
	}
}

func TestCertificateChoice(t *testing.T) {
	c, rc := server(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "device-link") {
			jsonReply(200, dlReply)(w, r)
			return
		}
		jsonReply(200, `{"sessionID":"cc-1","vc":{"type":"alphaNumeric5","value":"11111"}}`)(w, r)
	})
	ctx := context.Background()
	s, err := c.Sign.CertificateChoiceByEtsi(ctx, "PNOMN-12345678", nil)
	if err != nil || s.SessionID != "cc-1" || s.VC != "11111" || s.ExpiresAt.IsZero() || s.Sign != nil {
		t.Fatal(s, err)
	}
	req, body := rc.last()
	if req.URL.Path != "/signature/certificate-choice/notification/etsi/PNOMN-12345678" {
		t.Fatal(req.URL.Path)
	}
	// CA dto.CertificateChoiceRequest — үл мэдэгдэх талбар 400 тул яг эдгээр.
	if k := keys(bodyMap(t, body)); k != "certificateLevel,relyingPartyName,relyingPartyUUID" {
		t.Fatal(k)
	}
	d, err := c.Sign.CertificateChoiceDeviceLink(ctx, &CertChoiceOptions{CertificateLevel: LevelQSCD})
	if err != nil || d.SessionType != SessionCert || d.RelyingPartyName != creds.RPName {
		t.Fatal(d, err)
	}
	req, body = rc.last()
	if req.URL.Path != "/signature/certificate-choice/device-link/anonymous" || bodyMap(t, body)["certificateLevel"] != "QSCD" {
		t.Fatal(req.URL.Path, string(body))
	}
	if l, err := BuildDeviceLink(d.LinkInput(LinkQR, "eng")); err != nil || !strings.Contains(l, "sessionType=cert") {
		t.Fatal(l, err)
	}
	var de *DeviceLinkError
	if _, err := BuildDeviceLink(d.LinkInput(LinkWeb2App, "eng")); !errors.As(err, &de) {
		t.Fatal("cert choice-д callback байхгүй тул Web2App боломжгүй", err)
	}
}

func certChoiceResult(leaf *testCA) *SessionResult {
	return &SessionResult{
		State: StateComplete, EndResult: EndResultOK, DocumentNumber: "PNOMN-12345678-ABCD-Q", CertificateLevel: "QUALIFIED",
		CertificateDERB64: base64.StdEncoding.EncodeToString(leaf.cert.Raw),
	}
}

func TestValidateCertificateChoice(t *testing.T) {
	V := trusted(t)
	p := testPKI(t)
	sg, err := V.ValidateCertificateChoice(certChoiceResult(p.rsaLeaf), "cc-1")
	if err != nil {
		t.Fatal(err)
	}
	if sg.DocumentNumber != "PNOMN-12345678-ABCD-Q" || sg.CertChoiceSessionID != "cc-1" || sg.Subject.SerialNumber != "PNOMN-12345678" ||
		sg.CertificateDERB64 != base64.StdEncoding.EncodeToString(p.rsaLeaf.cert.Raw) {
		t.Fatalf("%+v", sg)
	}
	r := certChoiceResult(p.rsaLeaf)
	r.EndResult = EndResultUserRefusedCertChoice
	var sf *SessionFailedError
	if _, err := V.ValidateCertificateChoice(r, "cc-1"); !errors.As(err, &sf) || sf.EndResult != EndResultUserRefusedCertChoice {
		t.Fatal(err)
	}
	r = certChoiceResult(p.rsaLeaf)
	r.DocumentNumber = ""
	_, err = V.ValidateCertificateChoice(r, "cc-1")
	wantInvalid(t, err, "documentNumber")
	// Итгэлгүй гинж (trust anchor-гүй validator) — fail-closed.
	strict, _ := NewValidator(TrustConfig{})
	_, err = strict.ValidateCertificateChoice(certChoiceResult(p.rsaLeaf), "cc-1")
	wantInvalid(t, err, "trust anchor")
	// Зориулалт (v0.6.0-аас анхдагч): гарын үсгийн гэрчилгээ (contentCommitment) шаардана — нэвтрэлтийн профайл унана.
	authOnly := purposeLeaf(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection})
	_, err = V.ValidateCertificateChoice(certChoiceResult(authOnly), "cc-1")
	wantInvalid(t, err, "contentCommitment")
}

func TestDigestForSigner(t *testing.T) {
	c, rc := server(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "device-link") {
			jsonReply(200, dlReply)(w, r)
			return
		}
		jsonReply(200, `{"sessionID":"s-2","vc":{"type":"alphaNumeric5","value":"22222"}}`)(w, r)
	})
	ctx := context.Background()
	dtbs := sha256.Sum256([]byte("signedAttrs"))
	d := base64.StdEncoding.EncodeToString(dtbs[:])
	sg := &Signer{DocumentNumber: "PNOMN-12345678-ABCD-Q", CertChoiceSessionID: "cc-1"}

	s, err := c.Sign.DigestForSigner(ctx, sg, d, nil, &SignOptions{FileName: "a.pdf"})
	if err != nil {
		t.Fatal(err)
	}
	req, body := rc.last()
	m := bodyMap(t, body)
	if req.URL.Path != "/signature/notification/linked/PNOMN-12345678-ABCD-Q" || m["linkedSessionID"] != "cc-1" {
		t.Fatal(req.URL.Path, m)
	}
	spp := m["signatureProtocolParameters"].(map[string]any)
	if spp["signatureAlgorithm"] != "sha256WithRSAEncryption" || spp["digest"] != d ||
		s.Sign.SignatureAlgorithm != AlgSHA256WithRSA || s.Sign.HashAlgorithm != SHA256 {
		t.Fatal(spp, s.Sign)
	}

	if _, err := c.Sign.DigestForSigner(ctx, &Signer{DocumentNumber: "DOC-1"}, d, nil, nil); err != nil {
		t.Fatal(err)
	}
	req, body = rc.last()
	if req.URL.Path != "/signature/notification/document/DOC-1" || strings.Contains(string(body), "linkedSessionID") {
		t.Fatal(req.URL.Path, string(body))
	}

	dl, err := c.Sign.DeviceLinkForSigner(ctx, sg, d, nil, &SignOptions{CallbackURL: "https://rp.example.mn/cb"})
	if err != nil || dl.SessionType != SessionSign || dl.Sign.SignatureAlgorithm != AlgSHA256WithRSA {
		t.Fatal(dl, err)
	}
	req, body = rc.last()
	if req.URL.Path != "/signature/device-link/document/PNOMN-12345678-ABCD-Q" || strings.Contains(string(body), "linkedSessionID") {
		t.Fatal(req.URL.Path)
	}

	n := len(rc.reqs)
	for _, tc := range []struct {
		sg     *Signer
		digest string
		o      *SignOptions
	}{
		{nil, d, nil},
		{&Signer{}, d, nil},
		{sg, base64.StdEncoding.EncodeToString(make([]byte, 48)), nil}, // SHA-256-д 48 байт
		{sg, d, &SignOptions{HashAlgorithm: SHA512}},                   // SHA-512-д 32 байт
		{sg, "not base64!", nil},
	} {
		if _, err := c.Sign.DigestForSigner(ctx, tc.sg, tc.digest, nil, tc.o); err == nil {
			t.Fatalf("алдаа хүлээв: %+v", tc)
		}
	}
	if len(rc.reqs) != n {
		t.Fatal("буруу оролтод хүсэлт явав")
	}
}

func TestValidateSignExpectedAlgorithm(t *testing.T) {
	V := trusted(t)
	p := testPKI(t)
	dtbs := sha256.Sum256([]byte("signedAttrs"))
	d := base64.StdEncoding.EncodeToString(dtbs[:])
	mk := func(leaf *testCA, alg, signAlg string) *SessionResult {
		r := certChoiceResult(leaf)
		r.SignatureProtocol, r.SignatureAlgorithm = "RAW_DIGEST_SIGNATURE", alg
		r.SignatureAlgorithmParameters = &SignatureAlgorithmParameters{HashAlgorithm: "SHA-256"}
		r.SignatureValueB64 = signDigest(t, leaf.key, signAlg, crypto.SHA256, dtbs[:])
		return r
	}
	pkcs1 := ValidateSignOptions{ExpectedAlgorithm: AlgSHA256WithRSA}
	if _, err := V.ValidateSign(mk(p.rsaLeaf, "sha256WithRSAEncryption", "pkcs1"), d, SHA256, pkcs1); err != nil {
		t.Fatal(err)
	}
	// PKCS#1 v1.5 хүссэн session-д PSS хариу — татгалзана (хүсээгүй алгоритм).
	_, err := V.ValidateSign(mk(p.rsaLeaf, "rsassa-pss", "rsassa-pss"), d, SHA256, pkcs1)
	wantInvalid(t, err, "≠ хүссэн sha256WithRSAEncryption")
	// PSS-ийг тодорхой хүссэн бол зөвшөөрнө; эсрэгээр PKCS#1 хариу татгалзана.
	pss := ValidateSignOptions{ExpectedAlgorithm: AlgRSASSAPSS}
	if _, err := V.ValidateSign(mk(p.rsaLeaf, "rsassa-pss", "rsassa-pss"), d, SHA256, pss); err != nil {
		t.Fatal(err)
	}
	_, err = V.ValidateSign(mk(p.rsaLeaf, "sha256WithRSAEncryption", "pkcs1"), d, SHA256, pss)
	wantInvalid(t, err, "≠ хүссэн rsassa-pss")
	// Хуучин threshold-ECDSA credential: CA хүссэнээс үл хамааран ecdsa-with-SHA256 — EC гэрчилгээтэй үед л.
	if _, err := V.ValidateSign(mk(p.ecLeaf, "ecdsa-with-SHA256", "ecdsa"), d, SHA256, pkcs1); err != nil {
		t.Fatal(err)
	}
	// Хуучин зан (ExpectedAlgorithm "") — PSS хариу хүлээн авагдана.
	if _, err := V.ValidateSign(mk(p.rsaLeaf, "rsassa-pss", "rsassa-pss"), d, SHA256); err != nil {
		t.Fatal(err)
	}
	// ExpectedCertificate — certificate-choice-ийнхоос өөр гэрчилгээ (өөр утас) → татгалзана.
	_, err = V.ValidateSign(mk(p.ecLeaf, "ecdsa-with-SHA256", "ecdsa"), d, SHA256,
		ValidateSignOptions{ExpectedAlgorithm: AlgSHA256WithRSA, ExpectedCertificate: p.rsaLeaf.cert})
	wantInvalid(t, err, "certificate-choice")
	if _, err := V.ValidateSign(mk(p.rsaLeaf, "sha256WithRSAEncryption", "pkcs1"), d, SHA256,
		ValidateSignOptions{ExpectedAlgorithm: AlgSHA256WithRSA, ExpectedCertificate: p.rsaLeaf.cert}); err != nil {
		t.Fatal(err)
	}
}
