package pades

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
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

// sigObjs — баримтын гарын үсгийн толины объектын дугаарууд (precheck-ийн verified-ийн оронд; криптографгүй).
func sigObjs(t *testing.T, doc []byte) map[uint32]bool {
	t.Helper()
	sigs, _, _, err := scanSignatures(doc)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint32]bool{}
	for _, s := range sigs {
		out[s.obj] = true
	}
	return out
}

// TestResolveDocID — §6.6-ийн салаа бүр: гарын үсэггүй → opts эсвэл санамсаргүй; гарын үсэгтэй → (2.1) verify хуудас
// (маркераас түрүүлнэ), (2.2) маркертай дардас, олдсонтой opts.docId зөрвөл REQUEST_INVALID, (3) opts.docId, (4) хоосон —
// гарын үсэгтэй баримтад санамсаргүй docId хэзээ ч үүсгэхгүй.
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
		want   string // docId | random | "" (err бол хамаарахгүй)
		err    bool
	}{
		{"(2.1) verify хуудас маркераас түрүүлнэ", pageAndMarker, false, "", pageDocID, false},
		{"(2.1) хуудас = opts", pageAndMarker, false, pageDocID, pageDocID, false},
		{"(2.1) хуудас ≠ opts (маркертай тэнцүү ч)", pageAndMarker, false, otherDocID, "", true},
		{"(2.2) маркер", sealQR, false, "", qrSealDocID, false},
		{"(2.2) маркер = opts", sealQR, false, qrSealDocID, qrSealDocID, false},
		{"(2.2) маркер ≠ opts", sealQR, false, otherDocID, "", true},
		{"(3) олдсонгүй → opts (opt-in)", sealV12, false, otherDocID, otherDocID, false},
		{"(4) QR-гүй тамгатай, opts-гүй → хоосон", sealV12, false, "", "", false},
		{"(4) үл харагдах гарын үсэгтэй, opts-гүй → хоосон", invisible, false, "", "", false},
		{"(1) гарын үсэггүй → санамсаргүй", unsigned, true, "", random, false},
		{"(1) гарын үсэггүй → opts", unsigned, true, otherDocID, otherDocID, false},
	}
	for _, c := range cases {
		var verified map[uint32]bool
		if !c.newDoc {
			verified = sigObjs(t, c.doc)
		}
		got, err := resolveDocID(c.doc, c.newDoc, verified, c.given)
		switch {
		case c.err:
			if ErrorCode(err) != CodeRequestInvalid {
				t.Errorf("%s: хүлээсэн REQUEST_INVALID, авсан %q %v", c.name, got, err)
			}
		case err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want == random:
			if !uuidRe.MatchString(got) || got == otherDocID {
				t.Errorf("%s: санамсаргүй UUID хүлээсэн, авсан %q", c.name, got)
			}
		case got != c.want:
			t.Errorf("%s: %q, хүлээсэн %q", c.name, got, c.want)
		}
	}
}

// stampPDF — docIDFromStamps-ийн синтетик баримт: 1 Catalog, 2 Pages, 3 Page, дараа нь objs (4-өөс). Дардасны stream =
// маркер (docId, rev) + EMC.
func stampPDF(objs ...string) []byte {
	return rawPDF(append([]string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"}, objs...)...)
}

func stampStream(docID string, extra string) string {
	c := "/EIDVerify <</URL (https://ca.eidmongolia.mn/verify/" + docID + "/1)>> BDC\nEMC\n"
	return fmt.Sprintf("<< /Length %d%s >>\nstream\n%sendstream", len(c), extra, c)
}

func stampWidget(sig, form string) string {
	return "<< /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /P 3 0 R /F 4 /FT /Sig /T (S) /V " + sig + " /AP << /N " + form + " 0 R >> >>"
}

func stampSig(end int) string {
	return fmt.Sprintf("<< /Type /Sig /ByteRange [0 10 20 %d] /Contents <00> >>", end-20)
}

// TestDocIDFromStampsEarliest — §6.6 алхам 2.2: хамгийн эрт зурсан (ByteRange[2]+[3] бага) дардас — xref-ийн дарааллаар
// СҮҮЛД (объектын дугаар их) байсан ч; зөвхөн шалгасан гарын үсэг рүү шууд бус /V-тэй, гарын үсэг бүрт ганц widget;
// /Filter алга эсвэл null.
func TestDocIDFromStampsEarliest(t *testing.T) {
	const later, earlier, forged = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333"
	// 4 widget (хожуу, бага дугаар) → 6 sig (end 200); 7 widget (эрт, их дугаар) → 9 sig (end 50).
	base := []string{stampWidget("6 0 R", "5"), stampStream(later, ""), stampSig(200),
		stampWidget("9 0 R", "8"), stampStream(earlier, ""), stampSig(50)}
	verified := map[uint32]bool{6: true, 9: true}
	cases := []struct {
		name     string
		objs     []string
		verified map[uint32]bool
		want     string
	}{
		{"эрт зурсан нь их дугаартай", base, verified, earlier},
		{"шууд /V толь (end 0) — үл тооно", append(append([]string{}, base...),
			"<< /FT /Sig /V << /Type /Sig /ByteRange [0 0 0 0] /Contents <00> >> /AP << /N 11 0 R >> >>", stampStream(forged, "")),
			verified, earlier},
		{"зээлсэн /V (9-д 2 widget) — 9 бүхэлдээ үл тооно", append(append([]string{}, base...),
			stampWidget("9 0 R", "11"), stampStream(forged, "")), verified, later},
		{"шалгаагүй гарын үсэг рүү /V — үл тооно", append(append([]string{}, base...),
			stampWidget("12 0 R", "11"), stampStream(forged, ""), stampSig(30)), verified, earlier},
		{"/Filter [] — нэр дэвшигч биш", []string{stampWidget("6 0 R", "5"), stampStream(earlier, " /Filter []"), stampSig(50)},
			map[uint32]bool{6: true}, ""},
		{"/Filter null — нэр дэвшигч", []string{stampWidget("6 0 R", "5"), stampStream(earlier, " /Filter null"), stampSig(50)},
			map[uint32]bool{6: true}, earlier},
		{"verified хоосон", base, nil, ""},
	}
	for _, c := range cases {
		got, err := docIDFromStamps(stampPDF(c.objs...), c.verified)
		if err != nil || got != c.want {
			t.Errorf("%s: %q %v, хүлээсэн %q", c.name, got, err, c.want)
		}
	}
	v12 := readTestdata(t, "golden/output/seal-visible.pdf")
	if got, err := docIDFromStamps(v12, sigObjs(t, v12)); err != nil || got != "" {
		t.Fatalf("QR-гүй тамга: %q %v", got, err)
	}
	qr := readTestdata(t, "golden/output/seal-qr-visible.pdf")
	if got, err := docIDFromStamps(qr, sigObjs(t, qr)); err != nil || got != qrSealDocID {
		t.Fatalf("QR тамга: %q %v", got, err)
	}
}

// TestPrepareDocIDRule — Prepare-ийн түвшинд: QR тамгатай баримтад иргэн (харагдах ба үл харагдах) тамганы docId-г авна,
// харагдах нь rev 2-оор зурна; opts.docId зөрвөл REQUEST_INVALID. QR-гүй тамгатай баримтад харагдах иргэн docId-гүй бол
// REQUEST_INVALID (v0.30.0-тэй ижил), opts.docId-тэй бол түүгээр (opt-in).
func TestPrepareDocIDRule(t *testing.T) {
	p := loadOrCreatePKI(t)
	opts := func(docID string, visible bool) PrepareOptions {
		o := testOpts(p, p.citizen.cert)
		o.VerifyPage, o.FileName, o.DocID = false, "", docID
		if visible {
			o.Appearance = &Appearance{X: 340, Y: 36, Width: 220, Height: 64}
		}
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
	marker := func(id string) []byte { return []byte("/EIDVerify <</URL (" + pageVerifyURL + id + "/2)>> BDC\n") }
	sealQR := readTestdata(t, "golden/output/seal-qr-visible.pdf")
	id, pdf := prepared(t, sealQR, opts("", true))
	if id != qrSealDocID || !bytes.Contains(pdf[len(sealQR):], marker(qrSealDocID)) {
		t.Fatalf("QR тамгын дараах иргэн: docId %q", id)
	}
	if id, _ := prepared(t, sealQR, opts("", false)); id != qrSealDocID {
		t.Fatalf("QR тамгын дараах үл харагдах иргэн: docId %q", id)
	}
	for _, visible := range []bool{true, false} {
		if _, err := Prepare(sealQR, opts(otherDocID, visible)); ErrorCode(err) != CodeRequestInvalid {
			t.Fatalf("opts.docId ≠ маркер (visible %v): %v", visible, err)
		}
	}
	sealV12 := readTestdata(t, "golden/output/seal-visible.pdf")
	if _, err := Prepare(sealV12, opts("", true)); ErrorCode(err) != CodeRequestInvalid {
		t.Fatalf("QR-гүй тамгын дараах иргэн, docId-гүй: %v", err)
	}
	id, pdf = prepared(t, sealV12, opts(otherDocID, true))
	if id != otherDocID || !bytes.Contains(pdf[len(sealV12):], marker(otherDocID)) {
		t.Fatalf("QR-гүй тамгын дараах иргэн, opts.docId: %q", id)
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
