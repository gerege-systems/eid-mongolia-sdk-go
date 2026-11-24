package pades

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
)

// QR-тэй тамганы дардас (APPEARANCE_SPEC.md §6.5) ба Prepare-ийн docId дүрэм (§6.6) — golden v13-ийн гаралт дээр.

const (
	qrSealDocID = "8c9d0e1f-2a3b-4c4d-8e5f-6a7b8c9d0e1f" // golden seal-qr-visible
	pageDocID   = "6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f" // golden quartz-pdf13 (verify хуудас)
	otherDocID  = "0f1e2d3c-4b5a-4968-8776-5a4b3c2d1e0f"
)

func readTestdata(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel)) // #nosec G304 -- тест
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestResolveDocID — §6.6-ийн салаа бүр: (1) verify хуудас (дардасны маркераас түрүүлнэ), (2) хамгийн эрт зурсан
// маркертай дардас, (3) opts.docId (олдсонтой зөрвөл REQUEST_INVALID), (4) санамсаргүй — гарын үсэгтэй баримтад ч QR
// зурах үед; QR зурахгүй бол "".
func TestResolveDocID(t *testing.T) {
	pageAndMarker := readTestdata(t, "validate/input/seal-qr-docid-vs-page.pdf") // хуудас 6f0c…, маркер 0f1e…
	sealQR := readTestdata(t, "golden/output/seal-qr-visible.pdf")               // маркер 8c9d…, хуудасгүй
	sealV12 := readTestdata(t, "golden/output/seal-visible.pdf")                 // хуудас ба маркер алга
	invisible := readTestdata(t, "golden/output/quartz-pdf13-nopage.pdf")        // үл харагдах, хуудас алга
	unsigned := readInput(t, "quartz-pdf13.pdf")
	const random = "<random>"
	cases := []struct {
		name   string
		doc    []byte
		newDoc bool
		given  string
		qr     bool
		want   string // "" | docId | random; err бол хоосон
		err    bool
	}{
		{"(1) verify хуудас маркераас түрүүлнэ", pageAndMarker, false, "", true, pageDocID, false},
		{"(1) хуудас = opts", pageAndMarker, false, pageDocID, true, pageDocID, false},
		{"(1) хуудас ≠ opts (маркертай тэнцүү ч)", pageAndMarker, false, otherDocID, true, "", true},
		{"(2) маркер", sealQR, false, "", true, qrSealDocID, false},
		{"(2) маркер, QR зурахгүй гарын үсэгт ч", sealQR, false, "", false, qrSealDocID, false},
		{"(2) маркер = opts", sealQR, false, qrSealDocID, true, qrSealDocID, false},
		{"(2) маркер ≠ opts", sealQR, false, otherDocID, true, "", true},
		{"(3) олдсонгүй → opts", sealV12, false, otherDocID, true, otherDocID, false},
		{"(4) QR-гүй тамгатай баримт, QR → санамсаргүй", sealV12, false, "", true, random, false},
		{"(4) үл харагдах гарын үсэгтэй баримт, QR → санамсаргүй", invisible, false, "", true, random, false},
		{"(4) гарын үсэгтэй, QR зурахгүй → хоосон", sealV12, false, "", false, "", false},
		{"(4) гарын үсэггүй → санамсаргүй (өмнөхтэй ижил)", unsigned, true, "", false, random, false},
	}
	for _, c := range cases {
		got, err := resolveDocID(c.doc, c.newDoc, c.given, c.qr)
		switch {
		case c.err:
			if ErrorCode(err) != CodeRequestInvalid {
				t.Errorf("%s: хүлээсэн REQUEST_INVALID, авсан %q %v", c.name, got, err)
			}
		case err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want == random:
			if !uuidRe.MatchString(got) || got == qrSealDocID || got == pageDocID {
				t.Errorf("%s: санамсаргүй UUID хүлээсэн, авсан %q", c.name, got)
			}
		case got != c.want:
			t.Errorf("%s: %q, хүлээсэн %q", c.name, got, c.want)
		}
	}
}

// TestDocIDFromStampsEarliest — хоёр маркертай дардас (өөр docId) ба verify хуудасгүй: хамгийн эрт зурсан (ByteRange-ийн
// төгсгөл бага) дардасны docId.
func TestDocIDFromStampsEarliest(t *testing.T) {
	sealQR := readTestdata(t, "golden/output/seal-qr-visible.pdf")
	at := goldenTime.In(signingZone)
	vis := core.Visible{Page: 1, X: 3600, Y: 3600, W: 22000, H: 6400, Name: "TESTOV GOLDEN", Lang: "mn",
		Date: at.Format("2006-01-02 15:04") + " (+08)", URL: pageVerifyURL + otherDocID + "/2"}
	prep, err := core.PrepareSignatureVisible(sealQR, at, "TESTOV GOLDEN", "", vis)
	if err != nil {
		t.Fatal(err)
	}
	if got := docIDFromStamps(prep.PDF); got != qrSealDocID {
		t.Fatalf("%q, хүлээсэн %q", got, qrSealDocID)
	}
	if got := docIDFromStamps(readTestdata(t, "golden/output/seal-visible.pdf")); got != "" {
		t.Fatalf("QR-гүй тамга: %q", got)
	}
}

// TestPrepareDocIDRule — Prepare-ийн түвшинд: QR тамгатай баримтад иргэн тамганы docId-г авч rev 2-оор зурна; QR-гүй
// тамгатай баримтад шинэ санамсаргүй docId (өмнө REQUEST_INVALID байв); opts.docId зөрвөл REQUEST_INVALID.
func TestPrepareDocIDRule(t *testing.T) {
	p := loadOrCreatePKI(t)
	visible := func(docID string) PrepareOptions {
		o := testOpts(p, p.citizen.cert)
		o.VerifyPage, o.FileName, o.DocID = false, "", docID
		o.Appearance = &Appearance{X: 340, Y: 36, Width: 220, Height: 64}
		return o
	}
	prepared := func(t *testing.T, doc []byte, o PrepareOptions) (string, []byte) {
		t.Helper()
		prep, err := Prepare(doc, o)
		if err != nil {
			t.Fatal(err)
		}
		st, err := decodeState(prep.State)
		if err != nil {
			t.Fatal(err)
		}
		return prep.DocID, st.PDF
	}
	sealQR := readTestdata(t, "golden/output/seal-qr-visible.pdf")
	id, pdf := prepared(t, sealQR, visible(""))
	if id != qrSealDocID || !bytes.Contains(pdf[len(sealQR):], []byte("/EIDVerify <</URL ("+pageVerifyURL+qrSealDocID+"/2)>> BDC\n")) {
		t.Fatalf("QR тамгын дараах иргэн: docId %q", id)
	}
	if _, err := Prepare(sealQR, visible(otherDocID)); ErrorCode(err) != CodeRequestInvalid {
		t.Fatalf("opts.docId ≠ маркер: %v", err)
	}
	sealV12 := readTestdata(t, "golden/output/seal-visible.pdf")
	id, pdf = prepared(t, sealV12, visible(""))
	if !uuidRe.MatchString(id) || !bytes.Contains(pdf[len(sealV12):], []byte("/EIDVerify <</URL ("+pageVerifyURL+id+"/2)>> BDC\n")) {
		t.Fatalf("QR-гүй тамгын дараах иргэн: docId %q", id)
	}
}

// dtbsSealer — SealPDF-ийн Sealer: DTBS-ийг тэмдэглээд зогсооно (Complete-гүй — зөвхөн prepared байт хэрэгтэй).
type dtbsSealer struct {
	cert   []byte
	digest []byte
}

var errSealStop = errors.New("stop")

func (s *dtbsSealer) Certificate(context.Context, string) (*eid.SealCertificate, error) {
	return &eid.SealCertificate{OrgEtsi: "NTRMN-0000000", Certificate: s.cert, CertificateLevel: eid.LevelQualified}, nil
}

func (s *dtbsSealer) Seal(_ context.Context, _ string, digest []byte, _ eid.HashAlgorithm) (*eid.SealResult, error) {
	s.digest = digest
	return nil, errSealStop
}

// TestSealPDFStillQRless — энэ хувилбарт SealPDF QR-тэй тамга ГАРГАХГҮЙ: анхдагч автомат дардас ба тодорхой Appearance нь
// v0.30.0-ийн golden `seal-visible` / `seal-visible-en`-ийн DTBS-тэй байт-ижил (prepared PDF + signedAttrs; docId-гүй ч).
func TestSealPDFStillQRless(t *testing.T) {
	p := loadOrCreatePKI(t)
	if p.seal == nil {
		t.Fatal("pki/seal.pem алга")
	}
	var m goldenManifest
	if err := json.Unmarshal(readTestdata(t, "golden/manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, c := range m.Cases {
		want[c.Name] = c.Expect.DTBS
	}
	chain := [][]byte{p.ca04.cert.Raw, p.ca03.cert.Raw, p.ca02.cert.Raw}
	for _, c := range []struct {
		golden, input string
		o             SealOptions
	}{
		{"seal-visible", "libreoffice-contract.pdf", SealOptions{Reason: "Нэхэмжлэх"}},
		{"seal-visible-en", "quartz-pdf13.pdf", SealOptions{Appearance: &Appearance{X: 340, Y: 36, Width: 220, Height: 64, Lang: "en"}}},
	} {
		s := &dtbsSealer{cert: p.seal.cert.Raw}
		c.o.SigningTime, c.o.Chain = goldenTime, chain
		if _, err := SealPDF(context.Background(), s, "NTRMN-0000000", readInput(t, c.input), c.o); !errors.Is(err, errSealStop) {
			t.Fatalf("%s: %v", c.golden, err)
		}
		if got := hex.EncodeToString(s.digest); want[c.golden] == "" || got != want[c.golden] {
			t.Errorf("%s: SealPDF DTBS %s ≠ golden %s", c.golden, got, want[c.golden])
		}
	}
}
