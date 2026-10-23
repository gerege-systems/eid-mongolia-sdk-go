package pades

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// Synthetic "PDF images" for tests and golden v10 (APPEARANCE_SPEC.md §6): no binaries in the repo — the alpha channel
// is drawn here and zlib-compressed. The images are written into manifest.json (prepare.appearance), so native SDKs read
// them from there; regenerating with another Go version may change the zlib bytes (and then the v10 outputs) — the
// golden contract is the manifest, not this function. SHA256 stands in for the CA's PNG hash (sha256 of the raw alpha).

// testSignatureImage — 480×144 px handwriting-like stroke (dark blue ink).
func testSignatureImage() *PDFImage {
	const w, h = 480, 144
	return testImage(w, h, [3]int{18, 32, 110}, func(x, y float64) float64 {
		// A decaying wave plus an underline flourish.
		cy := 70 + 38*math.Sin(x/26)*math.Exp(-x/520) + 10*math.Sin(x/7)
		d := math.Abs(y - cy)
		if u := math.Abs(y - (118 - x/24)); x > 60 && x < 420 && u < d {
			d = u
		}
		return 3.2 - d
	})
}

// testStampImage — 300×300 px round organization stamp (two rings, a centre bar, violet ink).
func testStampImage() *PDFImage {
	const s = 300
	return testImage(s, s, [3]int{88, 52, 160}, func(x, y float64) float64 {
		r := math.Hypot(x-150, y-150)
		d := min(math.Abs(r-142), math.Abs(r-100)+1.5)
		if math.Abs(y-150) < 14 && math.Abs(x-150) < 70 {
			d = min(d, math.Abs(math.Abs(y-150)-14), math.Abs(math.Abs(x-150)-70))
		}
		return 4 - d
	})
}

// testImage — alpha = clamp(f(x+0.5, y+0.5)) × 255 (antialiased by distance), rows top-down.
func testImage(w, h int, color [3]int, f func(x, y float64) float64) *PDFImage {
	raw := make([]byte, 0, w*h)
	for y := range h {
		for x := range w {
			a := max(0, min(1, f(float64(x)+0.5, float64(y)+0.5)))
			raw = append(raw, byte(math.Round(a*255)))
		}
	}
	var z bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	sum := sha256.Sum256(raw)
	return &PDFImage{Width: w, Height: h, Color: color, Alpha: z.Bytes(), SHA256: hex.EncodeToString(sum[:])}
}

// badAlphaImage — a valid zlib stream that inflates to one byte too few (REQUEST_INVALID).
func badAlphaImage() *PDFImage {
	im := testSignatureImage()
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write(make([]byte, im.Width*im.Height-1))
	_ = zw.Close()
	im.Alpha = z.Bytes()
	return im
}

// fdictAlpha — the same zlib stream with FDICT set and DICTID 1 (Adler-32 of the empty dictionary): compress/zlib
// and most platform inflaters accept it, APPEARANCE_SPEC.md §6.1 does not (REQUEST_INVALID in every SDK).
func fdictAlpha(z []byte) []byte {
	cmf, flg := z[0], byte(0xC0|0x20)
	flg |= byte(31-(int(cmf)*256+int(flg))%31) % 31
	out := []byte{cmf, flg, 0, 0, 0, 1}
	return append(out, z[2:]...)
}

// TestAppearanceImageInput — APPEARANCE_SPEC.md §6.1 input checks (REQUEST_INVALID before the PDF is parsed), the
// default sizes (§6.3) and the registration images (§6.6).
func TestAppearanceImageInput(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(goldenDir, "input", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	mod := func(f func(im *PDFImage)) *PDFImage {
		im := testSignatureImage()
		f(im)
		return im
	}
	bad := map[string]*PDFImage{
		"sha256 том үсэг":  mod(func(im *PDFImage) { im.SHA256 = strings.ToUpper(im.SHA256) }),
		"sha256 богино":    mod(func(im *PDFImage) { im.SHA256 = im.SHA256[:63] }),
		"өнгө 256":         mod(func(im *PDFImage) { im.Color[1] = 256 }),
		"өнгө сөрөг":       mod(func(im *PDFImage) { im.Color[0] = -1 }),
		"өргөн 1601":       mod(func(im *PDFImage) { im.Width = 1601 }),
		"өндөр 0":          mod(func(im *PDFImage) { im.Height = 0 }),
		"alpha хоосон":     mod(func(im *PDFImage) { im.Alpha = nil }),
		"alpha zlib биш":   mod(func(im *PDFImage) { im.Alpha = []byte("not zlib") }),
		"alpha илүү байт":  mod(func(im *PDFImage) { im.Height-- }),
		"alpha дутуу байт": badAlphaImage(),
		"alpha ард хог":    mod(func(im *PDFImage) { im.Alpha = append(bytes.Clone(im.Alpha), 0) }),
		"alpha > 300 KiB":  mod(func(im *PDFImage) { im.Alpha = make([]byte, 300<<10+1) }),
		"alpha FDICT 1":    mod(func(im *PDFImage) { im.Alpha = fdictAlpha(im.Alpha) }),
	}
	for name, im := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := SuggestPlacement(doc, Appearance{X: 36, Y: 36, SignatureImage: im})
			if ErrorCode(err) != CodeRequestInvalid {
				t.Fatalf("REQUEST_INVALID хүлээсэн: %v", err)
			}
		})
	}
	for _, c := range []struct {
		a    Appearance
		w, h float64
	}{
		{Appearance{X: 36, Y: 36}, 220, 64},
		{Appearance{X: 36, Y: 36, SignatureImage: testSignatureImage()}, 220, 110},
		{Appearance{X: 36, Y: 36, StampImage: testStampImage()}, 240, 147.5},
		{Appearance{X: 36, Y: 36, SignatureImage: testSignatureImage(), StampImage: testStampImage()}, 240, 147.5},
		{Appearance{X: 36, Y: 36, Width: 300, Height: 180, StampImage: testStampImage()}, 300, 180},
	} {
		s, err := SuggestPlacement(doc, c.a)
		if err != nil || s.Width != c.w || s.Height != c.h {
			t.Errorf("хэмжээ %v×%v хүлээсэн: %+v %v", c.w, c.h, s, err)
		}
	}
	sig, stamp := testSignatureImage(), testStampImage()
	r, err := Registration(&Completed{DocID: "d", RevIndex: 2, FileName: "a.pdf", ClaimedRole: "x", Images: []eid.PDFSignatureImage{
		{Kind: eid.PDFImageSignature, SHA256: sig.SHA256}, {Kind: eid.PDFImageStamp, SHA256: stamp.SHA256}}},
		RegistrationOptions{OnBehalfOf: "NTRMN-1234567"})
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(r)
	if !bytes.Contains(j, []byte(`"images":[{"kind":"signature","sha256":"`+sig.SHA256+`"},{"kind":"stamp","sha256":"`+stamp.SHA256+`"}]`)) {
		t.Fatalf("images алга: %s", j)
	}
	r, _ = Registration(&Completed{DocID: "d", RevIndex: 2, FileName: "a.pdf"}, RegistrationOptions{})
	if j, _ := json.Marshal(r); bytes.Contains(j, []byte(`"images"`)) {
		t.Fatalf("зураггүйд images илгээхгүй: %s", j)
	}
}
