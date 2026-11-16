package pades

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// LTV цуглуулалтын OCSP-ийн зэрэгцээ байдал ба ocspGrace: root → caA → caB → leaf (P-256, тест бүрд шинэ). caA ба caB
// нь AIA OCSP + CDP CRL-тэй CA (үндэсний CA-ийн байрлал), leaf — гинжийн эхний гэрчилгээ. Сүлжээ — ltvNet (хүсэлт
// бүрийн зан төлөв; ctx-ийг хүндэтгэнэ, идэвхтэй хүсэлтийг тоолно).

var (
	ltvGen = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC) // TSA genTime (after)
	ltvNow = ltvGen.Add(30 * time.Second)
)

type lCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

type ltvPKI struct {
	root, caA, caB, leaf *lCert
	byName               map[string]*lCert // OCSP/CRL замын нэр → олгогч
	child                map[string]*lCert // олгогч → түүний олгосон гэрчилгээ (OCSPSigning EKU-гүй «responder»)
}

func newLTVPKI(t *testing.T) *ltvPKI {
	t.Helper()
	serial := int64(500)
	issue := func(parent *lCert, cn string, ca bool, name string) *lCert {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial++
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: ltvGen.Add(-24 * time.Hour), NotAfter: ltvGen.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if ca {
			tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
		}
		if name != "" {
			tmpl.OCSPServer = []string{"http://ocsp.ltv.test/" + name}
			tmpl.CRLDistributionPoints = []string{"http://crl.ltv.test/" + name + ".crl"}
		}
		pc, pk := tmpl, key
		if parent != nil {
			pc, pk = parent.cert, parent.key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, &key.PublicKey, pk)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return &lCert{cert: c, key: key}
	}
	p := &ltvPKI{}
	p.root = issue(nil, "TEST ONLY LTV Root", true, "")
	p.caA = issue(p.root, "TEST ONLY LTV CA A", true, "root")
	p.caB = issue(p.caA, "TEST ONLY LTV CA B", true, "a")
	p.leaf = issue(p.caB, "TEST ONLY LTV Leaf", false, "b")
	p.byName = map[string]*lCert{"root": p.root, "a": p.caA, "b": p.caB}
	p.child = map[string]*lCert{"root": p.caA, "a": p.caB, "b": p.leaf}
	return p
}

// ltvBehavior — нэг OCSP эсвэл CRL URL-ийн хариу. Тэг утга = шинэлэг, олгогчийн гарын үсэгтэй «good» / цэвэр CRL.
type ltvBehavior struct {
	hang         bool          // хэзээ ч хариулахгүй (хүсэлтийн ctx дуустал)
	delay        time.Duration // хариулахаас өмнө (ctx-ийг хүндэтгэнэ)
	missing      bool          // 404
	garbage      bool          // OCSP/CRL биш
	unauthorised bool          // OCSP-г OCSPSigning EKU-гүй гэрчилгээ зурсан
	revoked      bool          // OCSP revoked / CRL-д гэрчилгээ жагсаалттай
}

type ltvNet struct {
	t        *testing.T
	p        *ltvPKI
	ocsp     map[string]ltvBehavior
	crl      map[string]ltvBehavior
	hangTo   http.RoundTripper // тэг биш бол hang хүсэлтийг жинхэнэ сокет (httptest) руу дамжуулна
	hangURL  *url.URL
	inflight atomic.Int64
}

func (n *ltvNet) RoundTrip(r *http.Request) (*http.Response, error) {
	n.inflight.Add(1)
	defer n.inflight.Add(-1)
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".crl")
	iss := n.p.byName[name]
	var b ltvBehavior
	switch r.URL.Host {
	case "ocsp.ltv.test":
		b = n.ocsp[name]
	case "crl.ltv.test":
		b = n.crl[name]
	default:
		iss = nil
	}
	reply := func(status int, out []byte) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(out)), Header: http.Header{}, Request: r}, nil
	}
	if iss == nil {
		return reply(http.StatusNotFound, nil)
	}
	if b.hang {
		if n.hangTo != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Scheme, r2.URL.Host, r2.Host = n.hangURL.Scheme, n.hangURL.Host, ""
			r2.Body = io.NopCloser(bytes.NewReader(body))
			return n.hangTo.RoundTrip(r2)
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	if b.delay > 0 {
		tm := time.NewTimer(b.delay)
		defer tm.Stop()
		select {
		case <-tm.C:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	switch {
	case b.missing:
		return reply(http.StatusNotFound, nil)
	case b.garbage:
		return reply(http.StatusOK, []byte("not a revocation response"))
	}
	if r.URL.Host == "crl.ltv.test" {
		var es []x509.RevocationListEntry
		if b.revoked {
			es = append(es, x509.RevocationListEntry{SerialNumber: n.p.child[name].cert.SerialNumber, RevocationTime: ltvGen.Add(-time.Hour)})
		}
		out, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: ltvGen.Add(-time.Hour),
			NextUpdate: ltvGen.Add(30 * 24 * time.Hour), RevokedCertificateEntries: es}, iss.cert, iss.key)
		if err != nil {
			n.t.Error(err)
		}
		return reply(http.StatusOK, out)
	}
	req, err := ocsp.ParseRequest(body)
	if err != nil {
		return reply(http.StatusBadRequest, nil)
	}
	th := ltvGen.Add(3 * time.Second)
	tmpl := ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber, ThisUpdate: th, NextUpdate: th.Add(7 * 24 * time.Hour)}
	if b.revoked {
		tmpl.Status, tmpl.RevokedAt, tmpl.RevocationReason = ocsp.Revoked, ltvGen.Add(-time.Hour), ocsp.KeyCompromise
	}
	signer := iss
	if b.unauthorised {
		signer = n.p.child[name]
		tmpl.Certificate = signer.cert
	}
	out, err := ocsp.CreateResponse(iss.cert, signer.cert, tmpl, signer.key)
	if err != nil {
		n.t.Error(err)
	}
	return reply(http.StatusOK, out)
}

// collect — leaf гинжийг grace-тэй цуглуулна; буцахад нэг ч хүсэлт идэвхтэй үлдээгүйг (OCSP goroutine бүр дууссан)
// шалгана.
func (n *ltvNet) collect(ctx context.Context, t *testing.T, grace time.Duration) (dssResult, time.Duration) {
	t.Helper()
	f := newFetcher(&http.Client{Transport: n})
	start := time.Now()
	d, err := collectLTVGrace(ctx, f, ltvNow, ltvGen, grace, []*x509.Certificate{n.p.root.cert}, []*x509.Certificate{n.p.leaf.cert, n.p.caB.cert, n.p.caA.cert})
	elapsed := time.Since(start)
	if k := n.inflight.Load(); k != 0 {
		t.Fatalf("collectLTV буцсаны дараа %d хүсэлт идэвхтэй (goroutine алдагдсан)", k)
	}
	return dssResult{Certs: d.Certs, OCSPs: d.OCSPs, CRLs: d.CRLs, err: err}, elapsed
}

type dssResult struct {
	Certs, OCSPs, CRLs [][]byte
	err                error
}

// ocspCerts — OCSP хариу бүр аль гэрчилгээнийх (олгогчийн гарын үсэг, serial) — жагсаалтын дарааллаар.
func (p *ltvPKI) ocspCerts(t *testing.T, list [][]byte) []string {
	t.Helper()
	pairs := []struct {
		name      string
		c, issuer *lCert
	}{{"leaf", p.leaf, p.caB}, {"caB", p.caB, p.caA}, {"caA", p.caA, p.root}}
	var got []string
	for _, der := range list {
		for _, pr := range pairs {
			if r, err := ocsp.ParseResponseForCert(der, pr.c.cert, pr.issuer.cert); err == nil && r.SerialNumber.Cmp(pr.c.cert.SerialNumber) == 0 {
				got = append(got, pr.name)
			}
		}
	}
	return got
}

// crlIssuers — CRL бүрийн олгогч — жагсаалтын дарааллаар.
func (p *ltvPKI) crlIssuers(t *testing.T, list [][]byte) []string {
	t.Helper()
	var got []string
	for _, der := range list {
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		for name, c := range map[string]*lCert{"caB": p.caB, "caA": p.caA, "root": p.root} {
			if bytes.Equal(crl.RawIssuer, c.cert.RawSubject) {
				got = append(got, name)
			}
		}
	}
	return got
}

func joined(s []string) string { return strings.Join(s, ",") }

// TestCollectLTVHealthyChainOrder — эрүүл гинж: хариу урвуу дарааллаар ирсэн ч DSS (Certs, OCSPs, CRLs) гинжийн
// дарааллаар, OCSP ба CRL хоёулаа (дараалсан хувилбартай ижил). Complete-ийн байт-ижил гаралтыг TestGolden батална.
func TestCollectLTVHealthyChainOrder(t *testing.T) {
	p := newLTVPKI(t)
	n := &ltvNet{t: t, p: p, ocsp: map[string]ltvBehavior{"b": {delay: 120 * time.Millisecond}, "a": {delay: 60 * time.Millisecond}}}
	d, _ := n.collect(context.Background(), t, 2*time.Second)
	if d.err != nil {
		t.Fatal(d.err)
	}
	if len(d.Certs) != 3 || !bytes.Equal(d.Certs[0], p.leaf.cert.Raw) || !bytes.Equal(d.Certs[1], p.caB.cert.Raw) || !bytes.Equal(d.Certs[2], p.caA.cert.Raw) {
		t.Fatalf("Certs дараалал: %d", len(d.Certs))
	}
	if got := joined(p.ocspCerts(t, d.OCSPs)); got != "leaf,caB,caA" || len(d.OCSPs) != 3 {
		t.Fatalf("OCSPs %q", got)
	}
	if got := joined(p.crlIssuers(t, d.CRLs)); got != "caB,caA,root" {
		t.Fatalf("CRLs %q", got)
	}
}

// TestCollectLTVDeadOCSPWithValidCRL — хоёр CA-ийн OCSP хариугүй, CRL хүчинтэй: нийт НЭГ цонх (grace) зарцуулна (CA
// бүрд биш, 10 с timeout биш); DSS-д тэдгээрийн CRL, leaf-ийн OCSP.
func TestCollectLTVDeadOCSPWithValidCRL(t *testing.T) {
	const grace = 500 * time.Millisecond
	p := newLTVPKI(t)
	n := &ltvNet{t: t, p: p, ocsp: map[string]ltvBehavior{"a": {hang: true}, "root": {hang: true}}}
	d, elapsed := n.collect(context.Background(), t, grace)
	if d.err != nil {
		t.Fatal(d.err)
	}
	if elapsed < grace || elapsed >= 2*grace-100*time.Millisecond {
		t.Fatalf("хугацаа %v: нэг цонх (%v) хүлээгдэж байсан", elapsed, grace)
	}
	if got := joined(p.ocspCerts(t, d.OCSPs)); got != "leaf" {
		t.Fatalf("OCSPs %q", got)
	}
	if got := joined(p.crlIssuers(t, d.CRLs)); got != "caB,caA,root" {
		t.Fatalf("CRLs %q", got)
	}
}

// TestCollectLTVDeadOCSPRealSocket — холболт хүлээж аваад хариулдаггүй жинхэнэ HTTP сервер (үндэсний CA-ийн OCSP-ийн
// тохиолдол): цонхны дараа хүсэлт цуцлагдаж, сервер талын handler ч дуусна.
func TestCollectLTVDeadOCSPRealSocket(t *testing.T) {
	const grace = 300 * time.Millisecond
	var active atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		// net/http нь клиент салсныг (r.Context()) зөвхөн биеийг уншсаны дараа ажиглана.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	u, _ := url.Parse(srv.URL)
	p := newLTVPKI(t)
	n := &ltvNet{t: t, p: p, ocsp: map[string]ltvBehavior{"a": {hang: true}, "root": {hang: true}}, hangTo: srv.Client().Transport, hangURL: u}
	d, elapsed := n.collect(context.Background(), t, grace)
	if d.err != nil {
		t.Fatal(d.err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("хугацаа %v (цонх %v)", elapsed, grace)
	}
	deadline := time.Now().Add(2 * time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if k := active.Load(); k != 0 {
		t.Fatalf("сервер талд %d хүсэлт цуцлагдаагүй", k)
	}
}

// TestCollectLTVSlowOCSPWithoutCRL — хүчинтэй CRL-гүй CA-ийн удаан (цонхноос урт) OCSP-г таслахгүй хүлээнэ.
func TestCollectLTVSlowOCSPWithoutCRL(t *testing.T) {
	const grace, slow = 100 * time.Millisecond, 600 * time.Millisecond
	p := newLTVPKI(t)
	n := &ltvNet{t: t, p: p, ocsp: map[string]ltvBehavior{"a": {delay: slow}}, crl: map[string]ltvBehavior{"a": {missing: true}}}
	d, elapsed := n.collect(context.Background(), t, grace)
	if d.err != nil {
		t.Fatal(d.err)
	}
	if elapsed < slow {
		t.Fatalf("хугацаа %v < %v — OCSP-г хүлээгээгүй", elapsed, slow)
	}
	if got := joined(p.ocspCerts(t, d.OCSPs)); got != "leaf,caB,caA" {
		t.Fatalf("OCSPs %q", got)
	}
	if got := joined(p.crlIssuers(t, d.CRLs)); got != "caB,root" {
		t.Fatalf("CRLs %q", got)
	}
}

// TestCollectLTVLeafOCSPNotCut — гинжийн эхний гэрчилгээний (иргэн, TSA) OCSP-д цонх хамаарахгүй: CRL хүчинтэй ч удаан
// OCSP-г бүтнээр хүлээж DSS-д оруулна (thisUpdate > genTime дүрэм өөрчлөгдөөгүй).
func TestCollectLTVLeafOCSPNotCut(t *testing.T) {
	const grace, slow = 100 * time.Millisecond, 600 * time.Millisecond
	p := newLTVPKI(t)
	n := &ltvNet{t: t, p: p, ocsp: map[string]ltvBehavior{"b": {delay: slow}}}
	d, elapsed := n.collect(context.Background(), t, grace)
	if d.err != nil || elapsed < slow {
		t.Fatalf("%v %v", d.err, elapsed)
	}
	if got := joined(p.ocspCerts(t, d.OCSPs)); got != "leaf,caB,caA" {
		t.Fatalf("OCSPs %q", got)
	}
}

// TestCollectLTVBadOCSPFallsBack — хог, OCSPSigning EKU-гүй гэрчилгээний зурсан, 404 OCSP: хүчинтэй CRL байвал CRL-ээр
// (OCSP орохгүй); CRL-гүй бол LTV_UNAVAILABLE нөхцөл (revoked биш). Шалгах дүрэм өөрчлөгдөөгүй.
func TestCollectLTVBadOCSPFallsBack(t *testing.T) {
	for name, b := range map[string]ltvBehavior{"garbage": {garbage: true}, "unauthorised": {unauthorised: true}, "404": {missing: true}} {
		t.Run(name, func(t *testing.T) {
			p := newLTVPKI(t)
			n := &ltvNet{t: t, p: p, ocsp: map[string]ltvBehavior{"a": b}}
			d, _ := n.collect(context.Background(), t, 2*time.Second)
			if d.err != nil {
				t.Fatal(d.err)
			}
			if got := joined(p.ocspCerts(t, d.OCSPs)); got != "leaf,caA" {
				t.Fatalf("OCSPs %q", got)
			}
			n.crl = map[string]ltvBehavior{"a": {missing: true}}
			d, _ = n.collect(context.Background(), t, 2*time.Second)
			if !errors.Is(d.err, errLTV) || errors.Is(d.err, ErrCertificateRevoked) || !strings.Contains(d.err.Error(), p.caB.cert.SerialNumber.Text(16)) {
				t.Fatalf("%v", d.err)
			}
		})
	}
}

// TestCollectLTVRevokedIsFatal — «revoked» хатуу алдаа хэвээр: цонхонд ирсэн CA-ийн OCSP revoked (CRL цэвэр байсан ч),
// CRL-д жагсаалттай, leaf-ийн OCSP revoked.
func TestCollectLTVRevokedIsFatal(t *testing.T) {
	const grace = 500 * time.Millisecond
	for _, tc := range []struct {
		name      string
		ocsp, crl map[string]ltvBehavior
		serial    func(*ltvPKI) *big.Int
	}{
		{"CA OCSP revoked within grace", map[string]ltvBehavior{"a": {revoked: true, delay: 150 * time.Millisecond}}, nil, func(p *ltvPKI) *big.Int { return p.caB.cert.SerialNumber }},
		{"CA CRL revoked", nil, map[string]ltvBehavior{"root": {revoked: true}}, func(p *ltvPKI) *big.Int { return p.caA.cert.SerialNumber }},
		{"CA CRL revoked, OCSP dead", map[string]ltvBehavior{"root": {hang: true}}, map[string]ltvBehavior{"root": {revoked: true}}, func(p *ltvPKI) *big.Int { return p.caA.cert.SerialNumber }},
		{"leaf OCSP revoked", map[string]ltvBehavior{"b": {revoked: true, delay: 150 * time.Millisecond}}, nil, func(p *ltvPKI) *big.Int { return p.leaf.cert.SerialNumber }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newLTVPKI(t)
			n := &ltvNet{t: t, p: p, ocsp: tc.ocsp, crl: tc.crl}
			d, _ := n.collect(context.Background(), t, grace)
			if !errors.Is(d.err, ErrCertificateRevoked) || !strings.Contains(d.err.Error(), tc.serial(p).Text(16)) {
				t.Fatalf("%v", d.err)
			}
		})
	}
}

// TestCollectLTVCallerCancel — дуудагчийн ctx цуцлагдвал хариугүй OCSP/CRL-ийг хүлээхгүй буцна; goroutine үлдэхгүй.
func TestCollectLTVCallerCancel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ocsp, crl map[string]ltvBehavior
	}{
		{"OCSP dead, no CRL", map[string]ltvBehavior{"a": {hang: true}}, map[string]ltvBehavior{"a": {missing: true}}},
		{"OCSP and CRL dead", map[string]ltvBehavior{"a": {hang: true}, "root": {hang: true}}, map[string]ltvBehavior{"a": {hang: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newLTVPKI(t)
			n := &ltvNet{t: t, p: p, ocsp: tc.ocsp, crl: tc.crl}
			ctx, cancel := context.WithCancel(context.Background())
			tm := time.AfterFunc(200*time.Millisecond, cancel)
			defer tm.Stop()
			d, elapsed := n.collect(ctx, t, 5*time.Second)
			if d.err == nil || elapsed > 2*time.Second {
				t.Fatalf("%v %v", d.err, elapsed)
			}
		})
	}
}
