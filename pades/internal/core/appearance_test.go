package core

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/assets"
)

func TestNum100(t *testing.T) {
	for v, want := range map[int]string{0: "0", 100: "1", 150: "1.5", 105: "1.05", 59528: "595.28", -50: "-0.5", -1234: "-12.34", 7: "0.07"} {
		if got := Num100(v); got != want {
			t.Errorf("Num100(%d) = %q, хүлээсэн %q", v, got, want)
		}
	}
	if Round100(595.275) != 59528 || Round100(0.004) != 0 || Round100(-0.005) != 0 {
		t.Fatal("Round100")
	}
}

// TestVisibleRect — APPEARANCE_SPEC.md §1: CropBox-ийн эх (llx, lly ≠ 0) ба /Rotate 0/90/180/270.
func TestVisibleRect(t *testing.T) {
	box := [4]int{1000, 2000, 61200, 81200} // 602 × 792 pt, эх (10, 20)
	// Харагдах (36, 36) 220 × 64 pt.
	cases := map[int][4]int{
		0:   {4600, 5600, 26600, 12000},   // ux = llx + vx, uy = lly + vy
		90:  {51200, 5600, 57600, 27600},  // ux = urx − vy, uy = lly + vx
		180: {35600, 71200, 57600, 77600}, // ux = urx − vx, uy = ury − vy
		270: {4600, 55600, 11000, 77600},  // ux = llx + vy, uy = ury − vx
	}
	for rot, want := range cases {
		got, err := VisibleRect(box, rot, 3600, 3600, 22000, 6400)
		if err != nil || got != want {
			t.Errorf("rot %d: %v %v, хүлээсэн %v", rot, got, err, want)
		}
	}
	if _, err := VisibleRect(box, 90, 3600, 3600, 80000, 6400); !errors.Is(err, ErrAppearance) {
		t.Errorf("90°-д харагдах өргөн = 792 pt: %v", err)
	}
	if _, err := VisibleRect(box, 0, 59000, 0, 2000, 6400); !errors.Is(err, ErrAppearance) {
		t.Errorf("баруун ирмэгээс гарна: %v", err)
	}
}

// TestSealQRContent — APPEARANCE_SPEC.md §6.5: QR-тэй тамганы content stream = иргэний дардас (§3, үүрэггүй) яг тэр
// байтаар, зөвхөн label-ийн glyph-ууд тамганых; claimedRole хэзээ ч зурагдахгүй; 45 pt-оос намхан → ErrAppearance.
// URL хоосон бол QR-гүй тамга (§6.2) хэвээр — маркергүй.
func TestSealQRContent(t *testing.T) {
	reg, err := assets.Regular()
	if err != nil {
		t.Fatal(err)
	}
	bld, err := assets.Bold()
	if err != nil {
		t.Fatal(err)
	}
	w := &pageWriter{reg: reg, bld: bld}
	const url = "https://ca.eidmongolia.mn/verify/8c9d0e1f-2a3b-4c4d-8e5f-6a7b8c9d0e1f/1"
	for _, lang := range []string{"mn", "en"} {
		for _, rot := range []int{0, 90, 180, 270} {
			p := AppearanceParams{W: 22000, H: 6400, Rotate: rot, Name: "TEST ONLY Golden Org LLC", Role: "Захирал, Тест ХХК",
				Lang: lang, Date: "2026-10-14 12:00 (+08)", URL: url}
			cit := p
			cit.Role = ""
			c, err := AppearanceContent(cit, reg, bld)
			if err != nil {
				t.Fatal(err)
			}
			sp := p
			sp.Seal = true
			s, err := AppearanceContent(sp, reg, bld)
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Replace(c, []byte(w.glyphHex(1, AppearanceLabels[lang])), []byte(w.glyphHex(1, SealLabels[lang])), 1)
			if !bytes.Equal(s, want) || !bytes.HasPrefix(s, []byte("/EIDVerify <</URL ("+url+")>> BDC\n")) {
				t.Errorf("%s rot %d: QR тамга ≠ иргэний дардас + тамганы label:\n%s\n---\n%s", lang, rot, s, want)
			}
			sp.URL = ""
			plain, err := AppearanceContent(sp, reg, bld)
			if err != nil || bytes.Contains(plain, []byte("EIDVerify")) || bytes.Contains(plain, []byte(" re\n")) {
				t.Errorf("%s rot %d: QR-гүй тамга: %v", lang, rot, err)
			}
		}
	}
	p := AppearanceParams{W: 22000, H: 4499, Name: "TEST ONLY Golden Org LLC", Lang: "mn", Date: "2026-10-14 12:00 (+08)", URL: url, Seal: true}
	if _, err := AppearanceContent(p, reg, bld); !errors.Is(err, ErrAppearance) {
		t.Errorf("44.99 pt: %v", err)
	}
	p.H = 4500
	if _, err := AppearanceContent(p, reg, bld); err != nil {
		t.Errorf("45 pt: %v", err)
	}
}
