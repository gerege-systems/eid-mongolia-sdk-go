package validate

import (
	"bytes"
	"strings"
	"testing"
	"time"

	pades "github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/padestest"
)

// Харагдах гарын үсгийн own-signer хэлбэр (APPEARANCE_SPEC.md §5): яг PAdES бичигчийн widget + /AP-ийг хүлээн авч,
// бусад бүх хувилбарыг (2 дахь гарын үсэг криптограф хүчинтэй байсан ч) эхний гарын үсэгт modified_after_signing.

const visDocID = "6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f"

func visSpec(name string, rev int, tamper *pades.VisibleTamper) *pades.Visible {
	return &pades.Visible{Page: 1, X: 3600, Y: 3600, W: 22000, H: 6400, Name: name, Role: "Захирал, Тест ХХК (NTRMN-1234567)",
		Lang: "mn", Date: visTime.Format("2006-01-02 15:04") + " (+08)",
		URL: "https://ca.eidmongolia.mn/verify/" + visDocID + "/" + string(rune('0'+rev)), Tamper: tamper}
}

var visTime = time.Date(2026, 10, 14, 12, 0, 0, 0, time.FixedZone("+08", 8*3600))

func replaceBody(role, old, repl string) *pades.VisibleTamper {
	return &pades.VisibleTamper{Body: func(r string, b []byte) []byte {
		if r != role {
			return b
		}
		if !bytes.Contains(b, []byte(old)) {
			panic(role + ": " + old)
		}
		return bytes.Replace(b, []byte(old), []byte(repl), 1)
	}}
}

func TestOwnVisibleSignature(t *testing.T) {
	p := padestest.New(t)
	v := padesValidator(p)
	v.Extract = isolated(t) // prod-ийн зам (worker → Extract → profileOwnSigner)
	tsa := p.TSAServer(t, nil)
	alice := p.Citizen(t, "ALICE", "BOLD", "1111111111", 2048)
	bob := p.Citizen(t, "BOB", "DORJ", "2222222222", 2048)
	base := padesBase(t) // 2 хуудас
	one := p.Sign(t, base, alice, padestest.SignOptions{TSAURL: tsa, SigningTime: visTime})
	sign2 := func(t *testing.T, tamper *pades.VisibleTamper) []byte {
		return p.Sign(t, one, bob, padestest.SignOptions{TSAURL: tsa, SigningTime: visTime, Visible: visSpec("BOB DORJ", 2, tamper)})
	}

	t.Run("хүлээн авна", func(t *testing.T) {
		rep := mustPDF(t, v, sign2(t, nil))
		if rep.Indication != Valid || len(rep.Signatures) != 2 {
			t.Fatalf("%+v", rep)
		}
		var first, second SignatureReport
		for _, s := range rep.Signatures {
			wantPAdESValid(t, s, "PAdES-BASELINE-LT")
			if s.SignerName == "ALICE BOLD" {
				first = s
			} else {
				second = s
			}
		}
		if !first.ExtendedBySignaturesOnly || !first.VisibleLaterSignature || first.Visible || !second.Visible || second.VisibleLaterSignature {
			t.Fatalf("1: ext=%v visLater=%v vis=%v; 2: vis=%v visLater=%v", first.ExtendedBySignaturesOnly,
				first.VisibleLaterSignature, first.Visible, second.Visible, second.VisibleLaterSignature)
		}
		// Харагдах эхний гарын үсэг дээр 2 дахь харагдах: 2-р хуудас (pdfcpu-ийн ObjStm дотор — бичигч шууд объектоор
		// дахин бичнэ, APPEARANCE_SPEC.md §5).
		oneVis := p.Sign(t, base, alice, padestest.SignOptions{TSAURL: tsa, SigningTime: visTime, Visible: visSpec("ALICE BOLD", 1, nil)})
		spec := visSpec("BOB DORJ", 2, nil)
		spec.Page, spec.Role = 2, ""
		rep = mustPDF(t, v, p.Sign(t, oneVis, bob, padestest.SignOptions{TSAURL: tsa, SigningTime: visTime, Visible: spec}))
		if rep.Indication != Valid {
			t.Fatalf("харагдах × 2: %+v", rep)
		}
		for _, s := range rep.Signatures {
			if !s.Visible {
				t.Fatalf("visible=false: %s", s.SignerName)
			}
		}
	})

	attacks := map[string]*pades.VisibleTamper{
		"widget /A":               replaceBody("widget", "  /F 4\n", "  /F 4\n  /A << /S /URI /URI (https://evil.example/) >>\n"),
		"widget /AA":              replaceBody("widget", "  /F 4\n", "  /F 4\n  /AA << >>\n"),
		"widget /F 6 (hidden)":    replaceBody("widget", "/F 4\n", "/F 6\n"),
		"widget /Rect зөрүү":      replaceBody("widget", "/Rect [36 36 256 100]", "/Rect [36 36 256 101]"),
		"/AP /D нэмэлт":           replaceBody("widget", "/AP << /N ", "/AP << /D 1 0 R /N "),
		"AP хуучин объект заана":  replaceBody("form", "/Resources << /Font", "/Resources << /XObject << /X 1 0 R >> /Font"),
		"content stream өөрчлөлт": replaceBody("form", "\n1 w\n", "\n9 w\n"),
		"content: нэмэлт бичвэр":  replaceBody("form", "EMC", "BT /F1 9 Tf 0 0 Td <0041> Tj ET\nEMC"),
		"URL revIndex буруу":      replaceBody("form", "/2)>> BDC", "/3)>> BDC"),
		"URL docID өөр":           replaceBody("form", visDocID, "7f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f"),
		"/Matrix нэмэлт":          replaceBody("form", "/Subtype /Form", "/Subtype /Form /Matrix [1 0 0 1 0 0]"),
		"фонтын программ өөр":     replaceBody("F1.2", "/Flags 32", "/Flags 33"),
		"ToUnicode өөр":           replaceBody("F2.4", "endcmap", "endcmap "),
		"өөр хуудасны /Annots-д":  {AnnotsPage: 2},
		"аль ч /Annots-д ороогүй": {AnnotsPage: -1},
	}
	// ObjStm доторх хуучин объектыг шууд объектоор дахин бичих: зөвхөн widget нэмсэн хуудас / /Annots (§5). Ижил утгаар
	// эсвэл хуудас биш объект → татгалзана.
	view, err := openView(one, newPDFBudget())
	if err != nil {
		t.Fatal(err)
	}
	var page2, other int
	for num, e := range view.xref {
		if e.kind != entComp {
			continue
		}
		o, err := view.get(num)
		if err != nil {
			t.Fatal(err)
		}
		if d, ok := o.(pdfDict); ok && d["Type"] == pdfName("Page") {
			page2 = num
		} else if other == 0 || num < other {
			other = num
		}
	}
	if page2 == 0 || other == 0 {
		t.Fatalf("ObjStm-д хуудас/объект алга: %d %d", page2, other)
	}
	rewrite := func(num int) []byte {
		o, _ := view.get(num)
		return []byte(pdfText(o))
	}
	attacks["ObjStm хуудас ижил утгаар"] = &pades.VisibleTamper{Extra: map[uint32][]byte{uint32(page2): rewrite(page2)}}
	attacks["ObjStm өөр объект"] = &pades.VisibleTamper{Extra: map[uint32][]byte{uint32(other): rewrite(other)}}
	for name, tamper := range attacks {
		t.Run(name, func(t *testing.T) {
			rep := mustPDF(t, v, sign2(t, tamper))
			for _, s := range rep.Signatures {
				if s.SignerName == "ALICE BOLD" {
					wantModified(t, s)
					return
				}
			}
			t.Fatalf("эхний гарын үсэг алга: %+v", rep)
		})
	}
	// Харагдах widget, гэхдээ /Name нь дүрслэлийн нэрээс өөр (бичигч ийм зүйл бичихгүй — Prepare татгалзана).
	t.Run("нэр зөрүү", func(t *testing.T) {
		_, err := pades.PrepareSignatureVisible(one, visTime, "BOB DORJ", "", *visSpec("EVIL NAME", 2, nil))
		if err == nil || !strings.Contains(err.Error(), "/Name") {
			t.Fatalf("алдаа хүлээсэн: %v", err)
		}
	})
}
