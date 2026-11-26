package eid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

var updateConformance = flag.Bool("update-conformance", false, "testdata/conformance-ийг дахин бичих (conformance_gen_test.go)")

// TestConformanceCorpus — -update-conformance: корпусыг бичнэ; үгүй бол санах ойд дахин үүсгэсэн нь диск дээрхтэй
// байт-ижил байх ёстой (генератор/SDK өөрчлөгдөөд корпус шинэчлэгдээгүй → улаан).
func TestConformanceCorpus(t *testing.T) {
	got := generateConformance(t, *updateConformance)
	var onDisk []string
	_ = filepath.WalkDir(confDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(confDir, p)
			onDisk = append(onDisk, filepath.ToSlash(rel))
		}
		return nil
	})
	if *updateConformance {
		for _, rel := range onDisk {
			if _, ok := got[rel]; !ok {
				if err := os.Remove(filepath.Join(confDir, rel)); err != nil {
					t.Fatal(err)
				}
			}
		}
		for rel, b := range got {
			p := filepath.Join(confDir, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("testdata/conformance: %d файл бичив", len(got))
		return
	}
	var stale []string
	for rel, b := range got {
		disk, err := os.ReadFile(filepath.Join(confDir, rel))
		if err != nil || !bytes.Equal(disk, b) {
			stale = append(stale, rel)
		}
	}
	for _, rel := range onDisk {
		if _, ok := got[rel]; !ok {
			stale = append(stale, rel+" (илүү)")
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("testdata/conformance хуучирсан (go test -run TestConformanceCorpus -update-conformance):\n  %s", strings.Join(stale, "\n  "))
	}
}

func confLoad(t *testing.T, rel string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(confDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
}

func confPEM(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(confDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestConformanceManifest(t *testing.T) {
	var m struct {
		Version          string            `json:"version"`
		Files            map[string]string `json:"files"`
		DevicelinkGolden struct {
			GoPath string `json:"goPath"`
			SHA256 string `json:"sha256"`
		} `json:"devicelinkGolden"`
		MyQRVectors struct {
			GoPath string `json:"goPath"`
			SHA256 string `json:"sha256"`
		} `json:"myqrVectors"`
	}
	confLoad(t, "manifest.json", &m)
	if m.Version != confVersion || len(m.Files) == 0 {
		t.Fatalf("manifest: %s %d", m.Version, len(m.Files))
	}
	for rel, want := range m.Files {
		b, err := os.ReadFile(filepath.Join(confDir, rel))
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != want {
			t.Errorf("%s sha256 зөрөв", rel)
		}
	}
	for _, pin := range []struct{ path, sum string }{{m.DevicelinkGolden.GoPath, m.DevicelinkGolden.SHA256}, {m.MyQRVectors.GoPath, m.MyQRVectors.SHA256}} {
		b, err := os.ReadFile(pin.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != pin.sum {
			t.Errorf("%s sha256 ≠ manifest pin", pin.path)
		}
	}
}

// confReasons — Go-ийн ValidationError.Reason → корпусын тогтвортой reason key (README §reason keys). Дараалал чухал
// (илүү тодорхой нь эхэнд). Мессежийн текст корпуст ОРОХГҮЙ — зөвхөн энэ хүснэгтэд (SDK бүр өөрийнхийг).
var confReasons = []struct {
	re  *regexp.Regexp
	key string
}{
	{regexp.MustCompile(`(?i)session дуусаагүй`), "session.not_complete"},
	{regexp.MustCompile(`(?i)signatureProtocol \S+ ≠`), "protocol.mismatch"},
	{regexp.MustCompile(`(?i)хариунд гэрчилгээ алга`), "response.no_certificate"},
	{regexp.MustCompile(`(?i)хариунд гарын үсэг алга`), "response.no_signature"},
	{regexp.MustCompile(`(?i)documentNumber алга`), "response.no_document_number"},
	{regexp.MustCompile(`(?i)гэрчилгээ (задарсангүй|base64 буруу)`), "cert.malformed"},
	{regexp.MustCompile(`(?i)гинжийн гэрчилгээний хугацаа`), "chain.expired"},
	{regexp.MustCompile(`(?i)хүчинтэй болоогүй`), "cert.not_yet_valid"},
	{regexp.MustCompile(`(?i)гэрчилгээний хугацаа дууссан`), "cert.expired"},
	{regexp.MustCompile(`(?i)KeyUsage digitalSignature алга`), "purpose.auth_digital_signature"},
	{regexp.MustCompile(`(?i)ExtKeyUsage clientAuth алга`), "purpose.auth_client_auth"},
	{regexp.MustCompile(`(?i)KeyUsage nonRepudiation`), "purpose.sign_non_repudiation"},
	{regexp.MustCompile(`(?i)trust anchor тохируулаагүй`), "trust.no_anchor"},
	{regexp.MustCompile(`(?i)name constraints`), "chain.name_constraints"},
	{regexp.MustCompile(`(?i)critical extension`), "chain.critical_extension"},
	{regexp.MustCompile(`(?i)pathLenConstraint`), "chain.path_len"},
	{regexp.MustCompile(`(?i)ExtKeyUsage энэ үйлдэлд|CA-ийн ExtKeyUsage`), "chain.eku"},
	{regexp.MustCompile(`(?i)CA биш эсвэл keyCertSign|keyCertSign алга`), "chain.not_ca"},
	{regexp.MustCompile(`(?i)trust anchor \(Root CA\) хүрсэнгүй`), "chain.untrusted"},
	{regexp.MustCompile(`(?i)гинж хүчингүй`), "chain.invalid"},
	{regexp.MustCompile(`(?i)allowedIssuerSkis`), "issuer.not_allowed"},
	{regexp.MustCompile(`(?i)certificateLevel \S+ гэрчилгээнээс`), "level.claimed_higher"},
	{regexp.MustCompile(`(?i)түвшин хүрэлцэхгүй`), "level.insufficient"},
	{regexp.MustCompile(`(?i)qcStatements буруу`), "level.qc_malformed"},
	{regexp.MustCompile(`(?i)serverRandom`), "auth.server_random"},
	{regexp.MustCompile(`(?i)userChallenge буруу хэлбэр`), "auth.user_challenge"},
	{regexp.MustCompile(`(?i)санал болгосон урсгалд байхгүй`), "auth.flow_not_offered"},
	{regexp.MustCompile(`(?i)≠ эхлүүлсэн урсгал`), "flow.mismatch"},
	{regexp.MustCompile(`(?i)userChallengeVerifier заавал`), "auth.verifier_required"},
	{regexp.MustCompile(`(?i)userChallengeVerifier нь`), "auth.verifier_mismatch"},
	{regexp.MustCompile(`(?i)interactionTypeUsed алга`), "auth.interaction_type_missing"},
	{regexp.MustCompile(`(?i)initialCallbackUrl`), "auth.callback_url"},
	{regexp.MustCompile(`(?i)ACSP_V2 payload-той таарсангүй`), "auth.signature"},
	{regexp.MustCompile(`(?i)дэмжигдээгүй (signatureAlgorithm|hashAlgorithm)`), "alg.unsupported"},
	{regexp.MustCompile(`(?i)ECDSA credential зөвхөн SHA-256`), "alg.ecdsa_hash"},
	{regexp.MustCompile(`(?i)бус гэрчилгээтэй|түлхүүртэй таарахгүй`), "alg.key_mismatch"},
	{regexp.MustCompile(`(?i)MGF1`), "alg.mgf1"},
	{regexp.MustCompile(`(?i)saltLength`), "alg.salt_length"},
	{regexp.MustCompile(`(?i)signatureAlgorithm \S+ ≠ хүссэн`), "alg.mismatch"},
	{regexp.MustCompile(`(?i)hashAlgorithm \S+ ≠ хүссэн`), "alg.hash_mismatch"},
	{regexp.MustCompile(`(?i)certificate-choice-оор сонгосонтой`), "sign.certificate_mismatch"},
	{regexp.MustCompile(`(?i)digest урт`), "sign.digest_length"},
	{regexp.MustCompile(`(?i)digest base64`), "sign.digest_base64"},
	{regexp.MustCompile(`(?i)өгсөн digest-тэй таарсангүй`), "sign.signature"},
	{regexp.MustCompile(`(?i)цуцлагдсан`), "revocation.revoked"},
	{regexp.MustCompile(`(?i)revocation төлөв тогтоогдсонгүй`), "revocation.unknown"},
}

func confClassify(err error) confExpectErr {
	var sf *SessionFailedError
	if errors.As(err, &sf) {
		return confExpectErr{Class: "SessionFailedError", EndResult: sf.EndResult}
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		for _, r := range confReasons {
			if r.re.MatchString(ve.Reason) {
				return confExpectErr{Class: "ValidationError", Reason: r.key}
			}
		}
		return confExpectErr{Class: "ValidationError", Reason: "?" + ve.Reason}
	}
	return confExpectErr{Class: "?" + err.Error()}
}

func TestConformanceRPValidate(t *testing.T) {
	var f struct {
		Trust map[string]confTrust `json:"trust"`
		Cases []struct {
			Name    string            `json:"name"`
			Kind    string            `json:"kind"`
			Trust   string            `json:"trust"`
			Now     time.Time         `json:"now"`
			Session json.RawMessage   `json:"session"`
			ACSP    *ACSPContext      `json:"acsp"`
			Digest  string            `json:"digest"`
			Hash    string            `json:"hashAlgorithm"`
			Options map[string]string `json:"options"`
			SessID  string            `json:"certChoiceSessionId"`
			Expect  confExpect        `json:"expect"`
		} `json:"cases"`
	}
	confLoad(t, "rp-validate/cases.json", &f)
	if len(f.Cases) < 60 {
		t.Fatalf("cases: %d", len(f.Cases))
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			tr, ok := f.Trust[c.Trust]
			if !ok {
				t.Fatalf("trust %q алга", c.Trust)
			}
			cfg := TrustConfig{TrustAnchorsPEM: []string{}, IntermediatesPEM: []string{}, AllowedIssuerSKIs: tr.AllowedIssuerSKIs,
				RequiredLevel: CertificateLevel(tr.RequiredLevel), ClockSkew: time.Duration(tr.ClockSkewSeconds) * time.Second}
			for _, p := range tr.Anchors {
				cfg.TrustAnchorsPEM = append(cfg.TrustAnchorsPEM, confPEM(t, p))
			}
			for _, p := range tr.Intermediates {
				cfg.IntermediatesPEM = append(cfg.IntermediatesPEM, confPEM(t, p))
			}
			v, err := NewValidator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			v.now = func() time.Time { return c.Now }
			r, err := ParseSessionResult(c.Session)
			if err != nil {
				t.Fatal(err)
			}
			eo := c.Expect.OK
			if eo == nil {
				eo = &confExpectOK{}
			}
			var cert *x509.Certificate
			var alg string
			o := c.Options
			switch c.Kind {
			case "auth":
				var id *VerifiedIdentity
				id, err = v.ValidateAuth(r, c.ACSP, ValidateAuthOptions{ExpectedFlowType: FlowType(o["expectedFlowType"]),
					UserChallengeVerifier: o["userChallengeVerifier"]})
				if err == nil {
					cert = id.Certificate
					if id.DocumentNumber != eo.DocumentNumber || id.CertificateLevel != eo.CertificateLevel {
						t.Fatalf("identity %s %s", id.DocumentNumber, id.CertificateLevel)
					}
				}
			case "sign":
				so := ValidateSignOptions{ExpectedFlowType: FlowType(o["expectedFlowType"]), ExpectedAlgorithm: SignatureAlgorithm(o["expectedAlgorithm"])}
				if ec := o["expectedCertificate"]; ec != "" {
					der, _ := base64.StdEncoding.DecodeString(ec)
					if so.ExpectedCertificate, err = x509.ParseCertificate(der); err != nil {
						t.Fatal(err)
					}
				}
				var vs *VerifiedSignature
				vs, err = v.ValidateSign(r, c.Digest, HashAlgorithm(c.Hash), so)
				if err == nil {
					cert, alg = vs.Certificate, vs.SignatureAlgorithm
					if vs.DocumentNumber != eo.DocumentNumber || vs.CertificateLevel != eo.CertificateLevel {
						t.Fatalf("signature %s %s", vs.DocumentNumber, vs.CertificateLevel)
					}
				}
			case "certificateChoice":
				var s *Signer
				s, err = v.ValidateCertificateChoice(r, c.SessID)
				if err == nil {
					cert = s.Certificate
					if s.DocumentNumber != eo.DocumentNumber || s.CertificateLevel != eo.CertificateLevel ||
						s.CertChoiceSessionID != c.SessID || s.CertificateDERB64 != base64.StdEncoding.EncodeToString(cert.Raw) {
						t.Fatalf("signer %+v", s)
					}
				}
			default:
				t.Fatalf("kind %s", c.Kind)
			}
			if c.Expect.Error != nil {
				if err == nil {
					t.Fatalf("алдаа хүлээсэн %+v, амжилттай", *c.Expect.Error)
				}
				if got := confClassify(err); got != *c.Expect.Error {
					t.Fatalf("алдаа %+v ≠ хүлээсэн %+v (%v)", got, *c.Expect.Error, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("амжилт хүлээсэн: %v", err)
			}
			sum := sha256.Sum256(cert.Raw)
			s := ParseSubject(cert)
			e := c.Expect.OK
			if hex.EncodeToString(sum[:]) != e.CertificateSHA256 || alg != e.SignatureAlgorithm ||
				!reflect.DeepEqual(map[string]string{"serialNumber": s.SerialNumber, "givenName": s.GivenName, "surname": s.Surname,
					"country": s.Country, "commonName": s.CommonName}, e.Subject) {
				t.Fatalf("үр дүн: %+v %s", s, alg)
			}
		})
	}
}

// confNormJSON — JSON round trip (map[string]any / float64) — семантик харьцуулалтад.
func confNormJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func confPointerGet(v any, ptr string) any {
	for _, p := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

// confResolve — expect доторх "$request:<ptr>" утгыг бодит хүсэлтийн биеэс орлуулна.
func confResolve(v any, body any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = confResolve(e, body)
		}
	case []any:
		for i, e := range x {
			x[i] = confResolve(e, body)
		}
	case string:
		if ptr, ok := strings.CutPrefix(x, "$request:"); ok {
			return confPointerGet(body, ptr)
		}
	}
	return v
}

func TestConformanceWire(t *testing.T) {
	var f struct {
		Client struct {
			BaseURL   string `json:"baseUrl"`
			RPUUID    string `json:"rpUUID"`
			RPName    string `json:"rpName"`
			APISecret string `json:"apiSecret"`
		} `json:"client"`
		Cases []confWireCase `json:"cases"`
	}
	confLoad(t, "wire/cases.json", &f)
	b64 := regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var sentBody any
			rt := rtFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != c.Request.Method || r.URL.RequestURI() != c.Request.Path {
					t.Errorf("хүсэлт %s %s ≠ %s %s", r.Method, r.URL.RequestURI(), c.Request.Method, c.Request.Path)
				}
				for k, want := range c.Request.Headers {
					got := r.Header.Get(k)
					if k == "Content-Type" {
						got, _, _ = mime.ParseMediaType(got)
					}
					if got != want {
						t.Errorf("header %s: %q ≠ %q", k, got, want)
					}
				}
				if r.Body != nil {
					raw, _ := io.ReadAll(r.Body)
					if len(raw) > 0 {
						_ = json.Unmarshal(raw, &sentBody)
					}
				}
				want := confNormJSON(t, c.Request.Body)
				got := confNormJSON(t, sentBody)
				for ptr, format := range c.Request.Volatile {
					val, _ := confPointerGet(got, ptr).(string)
					dec, err := base64.StdEncoding.DecodeString(val)
					if format != "base64:64" || err != nil || len(dec) != 64 || !b64.MatchString(val) {
						t.Errorf("volatile %s: %q (%s)", ptr, val, format)
					}
					confPointerSet(got, ptr, confVolatile)
				}
				if !reflect.DeepEqual(got, want) {
					g, _ := json.Marshal(got)
					w, _ := json.Marshal(want)
					t.Errorf("хүсэлтийн бие\n got %s\nwant %s", g, w)
				}
				body, _ := json.Marshal(c.Response.Body)
				h := http.Header{"Content-Type": {"application/json"}}
				for k, v := range c.Response.Headers {
					h.Set(k, v)
				}
				return &http.Response{StatusCode: c.Response.Status, Header: h, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
			})
			cl, err := NewClient(Config{BaseURL: f.Client.BaseURL, Credentials: Credentials{RPUUID: f.Client.RPUUID, RPName: f.Client.RPName,
				APISecret: f.Client.APISecret}, HTTPClient: &http.Client{Transport: rt}, Trust: TrustConfig{AllowUntrusted: true}})
			if err != nil {
				t.Fatal(err)
			}
			res, err := confInvoke(t, cl, c.Call)
			var got map[string]any
			if err != nil {
				got = map[string]any{"error": confErrJSON(err)}
			} else {
				_, hasExp := c.Response.Body.(map[string]any)["expiresAt"]
				got = confWireExpect(res, false, hasExp)
			}
			want := confResolve(confNormJSON(t, c.Expect), confNormJSON(t, sentBody))
			if g := confNormJSON(t, got); !reflect.DeepEqual(g, want) {
				gb, _ := json.Marshal(g)
				wb, _ := json.Marshal(want)
				t.Fatalf("үр дүн\n got %s\nwant %s", gb, wb)
			}
		})
	}
}

func TestConformanceInteractions(t *testing.T) {
	var f struct {
		Cases []struct {
			Name         string        `json:"name"`
			Interactions []Interaction `json:"interactions"`
			JSON         string        `json:"json"`
			Base64       string        `json:"base64"`
		} `json:"cases"`
	}
	confLoad(t, "interactions_golden.json", &f)
	for _, c := range f.Cases {
		got, err := InteractionsToBase64(c.Interactions)
		raw, _ := base64.StdEncoding.DecodeString(c.Base64)
		if err != nil || got != c.Base64 || string(raw) != c.JSON {
			t.Errorf("%s: %s ≠ %s", c.Name, got, c.Base64)
		}
	}
}

func TestConformanceACSP(t *testing.T) {
	var f struct {
		Cases []struct {
			Name          string            `json:"name"`
			Params        map[string]string `json:"params"`
			HashAlgorithm string            `json:"hashAlgorithm"`
			Payload       string            `json:"payload"`
			Digest        string            `json:"digestB64"`
		} `json:"cases"`
	}
	confLoad(t, "acsp_v2.json", &f)
	for _, c := range f.Cases {
		p := c.Params
		in := ACSPV2Params{SchemeName: p["schemeName"], ServerRandom: p["serverRandom"], RPChallenge: p["rpChallenge"],
			UserChallenge: p["userChallenge"], RelyingPartyName: p["relyingPartyName"], BrokeredRpName: p["brokeredRpName"],
			Interactions: p["interactions"], InteractionTypeUsed: p["interactionTypeUsed"], InitialCallbackURL: p["initialCallbackUrl"],
			FlowType: p["flowType"]}
		d, err := ACSPV2Digest(in, HashAlgorithm(c.HashAlgorithm))
		if err != nil || string(BuildACSPV2Payload(in)) != c.Payload || base64.StdEncoding.EncodeToString(d) != c.Digest {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
}

func TestConformanceOCSP(t *testing.T) {
	var f struct {
		Cases []confOCSPCase `json:"cases"`
	}
	confLoad(t, "ocsp/cases.json", &f)
	cert := func(rel string) *x509.Certificate {
		b, _ := pem.Decode([]byte(confPEM(t, rel)))
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339, c.Now)
			if err != nil {
				t.Fatal(err)
			}
			rt := rtFunc(func(r *http.Request) (*http.Response, error) {
				rep, ok := c.HTTP[r.Method+" "+r.URL.String()]
				if !ok {
					rep = confHTTPReply{Status: 404}
				}
				body, _ := base64.StdEncoding.DecodeString(rep.BodyB64)
				return &http.Response{StatusCode: rep.Status, Header: http.Header{"Content-Type": {rep.ContentType}},
					Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
			})
			check := NewOCSPChecker(OCSPOptions{HTTPClient: &http.Client{Transport: rt}, Now: func() time.Time { return now }})
			st, err := check(context.Background(), cert(c.Certificate), cert(c.Issuer))
			if string(st) != c.Expect["status"] {
				t.Fatalf("status %s ≠ %s (%v)", st, c.Expect["status"], err)
			}
			var oe *OCSPError
			kind := ""
			if errors.As(err, &oe) {
				kind = string(oe.Kind)
			}
			if kind != c.Expect["errorKind"] {
				t.Fatalf("errorKind %q ≠ %q (%v)", kind, c.Expect["errorKind"], err)
			}
		})
	}
}
