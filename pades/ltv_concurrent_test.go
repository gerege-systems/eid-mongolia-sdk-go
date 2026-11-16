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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// LTV цуглуулалтын дараалал гэрчилгээний үүргээр: root → caA → caB → leaf (P-256, тест бүрд шинэ). caA ба caB нь AIA
// OCSP + CDP CRL-тэй CA (үндэсний CA-ийн байрлал) — CRL эхэлж, хүчинтэй бол OCSP асуухгүй; leaf — гинжийн эхний
// гэрчилгээ, OCSP эхэлж. Сүлжээ — ltvNet (хүсэлт бүрийн зан төлөв; ctx-ийг хүндэтгэнэ, OCSP хүсэлт ба идэвхтэй хүсэлтийг
// тоолно).

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
	expired      bool          // CRL-ийн nextUpdate өнгөрсөн
}

type ltvNet struct {
	t        *testing.T
	p        *ltvPKI
	ocsp     map[string]ltvBehavior
	crl      map[string]ltvBehavior
	hangTo   http.RoundTripper // тэг биш бол hang хүсэлтийг жинхэнэ сокет (httptest) руу дамжуулна
	hangURL  *url.URL
	inflight atomic.Int64
	mu       sync.Mutex
	ocspReq  map[string]int // OCSP замын нэр → хүсэлтийн тоо
}

func (n *ltvNet) ocspRequests(name string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ocspReq[name]
}

func (n *ltvNet) RoundTrip(r *http.Request) (*http.Response, error) {
	n.inflight.Add(1)
	defer n.inflight.Add(-1)
	if err := r.Context().Err(); err != nil {
		return nil, err // net/http.Transport-тэй адил: цуцлагдсан хүсэлт явахгүй
	}
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
		n.mu.Lock()
		if n.ocspReq == nil {
			n.ocspReq = map[string]int{}
		}
		n.ocspReq[name]++
		n.mu.Unlock()
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
		this, next := ltvGen.Add(-time.Hour), ltvGen.Add(30*24*time.Hour)
		if b.expired {
			this, next = ltvGen.Add(-60*24*time.Hour), ltvGen.Add(-30*24*time.Hour)
		}
		signer := iss
		if b.unauthorised {
			signer = n.p.child[name] // өөр олгогчийн нэр/түлхүүр
		}
		out, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: this,
			NextUpdate: next, RevokedCertificateEntries: es}, signer.cert, signer.key)
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

// collect — leaf гинжийг цуглуулна (хүсэлт бүрийн timeout); буцахад нэг ч хүсэлт идэвхтэй үлдээгүйг (goroutine бүр
// дууссан) шалгана.
func (n *ltvNet) collect(ctx context.Context, t *testing.T, timeout time.Duration) (dssResult, time.Duration) {
	t.Helper()
	f := newFetcher(&http.Client{Transport: n})
	f.timeout = timeout
	start := time.Now()
	d, err := collectLTV(ctx, f, ltvNow, ltvGen, []*x509.Certificate{n.p.root.cert}, []*x509.Certificate{n.p.leaf.cert, n.p.caB.cert, n.p.caA.cert})
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

// TestCollectLTVHealthyChain — эрүүл гинж: leaf-д OCSP + CRL, CA-д зөвхөн CRL (CA-ийн OCSP руу НЭГ Ч хүсэлт үгүй);
// DSS гинжийн дарааллаар.
func TestCollectLTVHealthyChain(t *testing.T) {
	p := newLTVPKI(t)
	n := &ltvNet{t: t, p: p, crl: map[string]ltvBehavior{"b": {delay: 100 * time.Millisecond}}}
	d, _ := n.collect(context.Background(), t, httpTimeout)
	if d.err != nil {
		t.Fatal(d.err)
	}
	if len(d.Certs) != 3 || !bytes.Equal(d.Certs[0], p.leaf.cert.Raw) || !bytes.Equal(d.Certs[1], p.caB.cert.Raw) || !bytes.Equal(d.Certs[2], p.caA.cert.Raw) {
		t.Fatalf("Certs дараалал: %d", len(d.Certs))
	}
	if got := joined(p.ocspCerts(t, d.OCSPs)); got != "leaf" {
		t.Fatalf("OCSPs %q", got)
	}
	if got := joined(p.crlIssuers(t, d.CRLs)); got != "caB,caA,root" {
		t.Fatalf("CRLs %q", got)
	}
	if a, r := n.ocspRequests("a"), n.ocspRequests("root"); a != 0 || r != 0 {
		t.Fatalf("CA-ийн OCSP хүсэлт: a=%d root=%d", a, r)
	}
}

// TestCollectLTVCAOCSPNotContacted — CA-ийн OCSP responder холболт хүлээж аваад хариулдаггүй (жинхэнэ сокет), CRL
// хүчинтэй: сервер нэг ч хүсэлт хүлээж авахгүй, цуглуулалт хүлээлтгүй.
func TestCollectLTVCAOCSPNotContacted(t *testing.T) {
	var got atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
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
	d, elapsed := n.collect(context.Background(), t, httpTimeout)
	if d.err != nil {
		t.Fatal(d.err)
	}
	if k := got.Load(); k != 0 || n.ocspRequests("a") != 0 || n.ocspRequests("root") != 0 || elapsed > 2*time.Second {
		t.Fatalf("сервер %d хүсэлт авсан, %v", k, elapsed)
	}
}

// TestCollectLTVCAOCSPFallback — CA-д хүчинтэй CRL алга (404, хог, хугацаа дууссан, өөр олгогчийн): OCSP руу (энгийн
// timeout, удаан ч хүлээнэ) — DSS-д тэр CA-ийн OCSP; OCSP ч хүчингүй бол LTV_UNAVAILABLE нөхцөл (revoked биш).
func TestCollectLTVCAOCSPFallback(t *testing.T) {
	for name, b := range map[string]ltvBehavior{"404": {missing: true}, "garbage": {garbage: true}, "expired": {expired: true}, "foreign issuer": {unauthorised: true}} {
		t.Run(name, func(t *testing.T) {
			p := newLTVPKI(t)
			n := &ltvNet{t: t, p: p, crl: map[string]ltvBehavior{"a": b}, ocsp: map[string]ltvBehavior{"a": {delay: 300 * time.Millisecond}}}
			d, elapsed := n.collect(context.Background(), t, httpTimeout)
			if d.err != nil {
				t.Fatal(d.err)
			}
			if got := joined(p.ocspCerts(t, d.OCSPs)); got != "leaf,caB" || elapsed < 300*time.Millisecond {
				t.Fatalf("OCSPs %q, %v", got, elapsed)
			}
			if got := joined(p.crlIssuers(t, d.CRLs)); got != "caB,root" {
				t.Fatalf("CRLs %q", got)
			}
			if n.ocspRequests("a") != 1 || n.ocspRequests("root") != 0 {
				t.Fatalf("OCSP хүсэлт a=%d root=%d", n.ocspRequests("a"), n.ocspRequests("root"))
			}
			for _, bad := range []ltvBehavior{{garbage: true}, {unauthorised: true}, {missing: true}} {
				n.ocsp = map[string]ltvBehavior{"a": bad}
				d, _ = n.collect(context.Background(), t, httpTimeout)
				if !errors.Is(d.err, errLTV) || errors.Is(d.err, ErrCertificateRevoked) || !strings.Contains(d.err.Error(), p.caB.cert.SerialNumber.Text(16)) {
					t.Fatalf("%+v: %v", bad, d.err)
				}
			}
		})
	}
}

// TestCollectLTVLeafOCSPFirst — leaf: удаан OCSP-г хүлээж OCSP + CRL хоёуланг шигтгэнэ; хариугүй OCSP → timeout-ын
// дараа CRL-ээр (OCSP-гүй).
func TestCollectLTVLeafOCSPFirst(t *testing.T) {
	const slow = 600 * time.Millisecond
	p := newLTVPKI(t)
	n := &ltvNet{t: t, p: p, ocsp: map[string]ltvBehavior{"b": {delay: slow}}}
	d, elapsed := n.collect(context.Background(), t, httpTimeout)
	if d.err != nil || elapsed < slow {
		t.Fatalf("%v %v", d.err, elapsed)
	}
	if got := joined(p.ocspCerts(t, d.OCSPs)); got != "leaf" {
		t.Fatalf("OCSPs %q", got)
	}
	if got := joined(p.crlIssuers(t, d.CRLs)); got != "caB,caA,root" {
		t.Fatalf("CRLs %q", got)
	}

	const timeout = 300 * time.Millisecond
	n.ocsp = map[string]ltvBehavior{"b": {hang: true}}
	d, elapsed = n.collect(context.Background(), t, timeout)
	if d.err != nil || elapsed < timeout || elapsed > 2*time.Second {
		t.Fatalf("%v %v", d.err, elapsed)
	}
	if len(d.OCSPs) != 0 {
		t.Fatalf("OCSPs %d", len(d.OCSPs))
	}
	if got := joined(p.crlIssuers(t, d.CRLs)); got != "caB,caA,root" {
		t.Fatalf("CRLs %q", got)
	}
}

// TestCollectLTVRevokedIsFatal — «revoked» хатуу алдаа: CA-ийн CRL (OCSP хариугүй ч), CA-ийн OCSP нөөц, leaf-ийн OCSP
// (CRL цэвэр ч), leaf-ийн CRL (OCSP good ч).
func TestCollectLTVRevokedIsFatal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ocsp, crl map[string]ltvBehavior
		serial    func(*ltvPKI) *big.Int
	}{
		{"CA CRL revoked", map[string]ltvBehavior{"root": {hang: true}}, map[string]ltvBehavior{"root": {revoked: true}}, func(p *ltvPKI) *big.Int { return p.caA.cert.SerialNumber }},
		{"CA OCSP fallback revoked", map[string]ltvBehavior{"a": {revoked: true}}, map[string]ltvBehavior{"a": {missing: true}}, func(p *ltvPKI) *big.Int { return p.caB.cert.SerialNumber }},
		{"leaf OCSP revoked", map[string]ltvBehavior{"b": {revoked: true, delay: 150 * time.Millisecond}}, nil, func(p *ltvPKI) *big.Int { return p.leaf.cert.SerialNumber }},
		{"leaf CRL revoked", nil, map[string]ltvBehavior{"b": {revoked: true}}, func(p *ltvPKI) *big.Int { return p.leaf.cert.SerialNumber }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newLTVPKI(t)
			n := &ltvNet{t: t, p: p, ocsp: tc.ocsp, crl: tc.crl}
			d, _ := n.collect(context.Background(), t, httpTimeout)
			if !errors.Is(d.err, ErrCertificateRevoked) || !strings.Contains(d.err.Error(), tc.serial(p).Text(16)) {
				t.Fatalf("%v", d.err)
			}
		})
	}
}

// TestCollectLTVCallerCancel — дуудагчийн ctx цуцлагдвал хариугүй OCSP/CRL-ийг хүлээхгүй буцна; хүсэлт үлдэхгүй.
func TestCollectLTVCallerCancel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ocsp, crl map[string]ltvBehavior
	}{
		{"leaf OCSP dead", map[string]ltvBehavior{"b": {hang: true}}, nil},
		{"CA CRL dead", nil, map[string]ltvBehavior{"a": {hang: true}}},
		{"CA CRL missing, OCSP dead", map[string]ltvBehavior{"a": {hang: true}}, map[string]ltvBehavior{"a": {missing: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newLTVPKI(t)
			n := &ltvNet{t: t, p: p, ocsp: tc.ocsp, crl: tc.crl}
			ctx, cancel := context.WithCancel(context.Background())
			tm := time.AfterFunc(200*time.Millisecond, cancel)
			defer tm.Stop()
			d, elapsed := n.collect(ctx, t, httpTimeout)
			if d.err == nil || elapsed > 2*time.Second {
				t.Fatalf("%v %v", d.err, elapsed)
			}
		})
	}
}
