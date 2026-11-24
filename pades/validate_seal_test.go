package pades

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
)

// Тамганы дардас (APPEARANCE_SPEC.md §6) — ValidatePDF conformance (pades/testdata/validate, v12). Эерэг тохиолдлууд нь
// golden/output-ийн тамгатай гаралт; сөрөг хоёр нь гэрчилгээтэй таарахгүй дардастай 2 дахь гарын үсэг (иргэний гарын
// үсэгтэй golden/output/quartz-pdf13.pdf дээр, timestamp/DSS-гүй) — эхний иргэний гарын үсэг modified_after_signing.
func sealVCases() []vCase {
	return []vCase{
		{Name: "seal-visible", Input: "golden/output/seal-visible.pdf", Offline: true},
		{Name: "seal-visible-en", Input: "golden/output/seal-visible-en.pdf", Offline: true},
		{Name: "seal-after-two-citizens", Input: "golden/output/seal-visible-third.pdf", Offline: true},
		{Name: "seal-stamp-citizen-cert", Input: "validate/input/seal-stamp-citizen-cert.pdf", Offline: true},
		{Name: "citizen-stamp-seal-cert", Input: "validate/input/citizen-stamp-seal-cert.pdf", Offline: true},
		// v13 — QR-тэй тамганы дардас (APPEARANCE_SPEC.md §6.5). Эерэг: golden/output-ийн шинэ тохиолдлууд (QR-гүй
		// тамгын дараах иргэн өөр docId-тай — хоёр дардасны docId зөрөх нь өөрчлөлт биш).
		{Name: "seal-qr-visible", Input: "golden/output/seal-qr-visible.pdf", Offline: true},
		{Name: "seal-qr-visible-en", Input: "golden/output/seal-qr-visible-en.pdf", Offline: true},
		{Name: "seal-qr-rotated90", Input: "golden/output/seal-qr-rotated90.pdf", Offline: true},
		{Name: "citizen-then-seal-qr", Input: "golden/output/citizen-then-seal-qr.pdf", Offline: true},
		{Name: "seal-qr-then-citizen", Input: "golden/output/seal-qr-then-citizen.pdf", Offline: true},
		{Name: "seal-qr-then-seal-qr", Input: "golden/output/seal-qr-then-seal-qr.pdf", Offline: true},
		{Name: "sealv12-then-citizen", Input: "golden/output/sealv12-then-citizen.pdf", Offline: true},
		// Сөрөг (2 дахь гарын үсэг B-B, golden/output/quartz-pdf13.pdf дээр): эхний гарын үсэг modified_after_signing.
		{Name: "seal-qr-citizen-cert", Input: "validate/input/seal-qr-citizen-cert.pdf", Offline: true},
		{Name: "seal-qr-with-role", Input: "validate/input/seal-qr-with-role.pdf", Offline: true},
		{Name: "seal-qr-wrong-rev", Input: "validate/input/seal-qr-wrong-rev.pdf", Offline: true},
		{Name: "seal-qr-docid-vs-page", Input: "validate/input/seal-qr-docid-vs-page.pdf", Offline: true},
		{Name: "seal-v12-with-marker", Input: "validate/input/seal-v12-with-marker.pdf", Offline: true},
		{Name: "seal-qr-height-44pt", Input: "validate/input/seal-qr-height-44pt.pdf", Offline: true},
		// Хяналт: сөрөг векторуудын үүсгэгч (vStampRev-ийн анхдагч, e-Seal, QR) — хүлээн авна; сөрөг бүр үүнээс нэг талбараар
		// ялгаатай. Дараа нь маркерын хэлбэрийн сөрөг: QR-гүй тамгын дотор маркер offset 0 биш; FlateDecode-той QR тамга;
		// CRLF; том үсгийн uuid; rev «02».
		{Name: "seal-qr-control", Input: "validate/input/seal-qr-control.pdf", Offline: true},
		{Name: "seal-marker-not-at-start", Input: "validate/input/seal-marker-not-at-start.pdf", Offline: true},
		{Name: "seal-qr-flate", Input: "validate/input/seal-qr-flate.pdf", Offline: true},
		{Name: "seal-qr-marker-crlf", Input: "validate/input/seal-qr-marker-crlf.pdf", Offline: true},
		{Name: "seal-qr-control-nopage", Input: "validate/input/seal-qr-control-nopage.pdf", Offline: true},
		{Name: "seal-qr-uuid-uppercase", Input: "validate/input/seal-qr-uuid-uppercase.pdf", Offline: true},
		{Name: "seal-qr-rev-02", Input: "validate/input/seal-qr-rev-02.pdf", Offline: true},
	}
}

// sealVInputs — сөрөг оролтууд (-update): иргэний гэрчилгээ + тамганы дардас; e-Seal гэрчилгээ + иргэний дардас.
func sealVInputs(t *testing.T, p *goldenPKI) map[string][]byte {
	t.Helper()
	if p.seal == nil {
		t.Fatal("pki/seal.pem алга — эхлээд `go test ./pades -run '^TestGolden$' -update`")
	}
	base, err := os.ReadFile(filepath.Join(goldenDir, "output", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	docID := docIDFromPage(base)
	if docID == "" {
		t.Fatal("base: docId алга")
	}
	url := pageVerifyURL + docID + "/2"
	sealQR := func(v *core.Visible) { v.Seal = true }
	noPage, err := os.ReadFile(filepath.Join(goldenDir, "output", "quartz-pdf13-nopage.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"seal-stamp-citizen-cert": vMismatchedStamp(t, p, base, p.citizen, true),
		"citizen-stamp-seal-cert": vMismatchedStamp(t, p, base, p.seal, false),
		// v13 (§6.3 delta): иргэний гэрчилгээ + QR-тэй тамга; e-Seal + үүргийн мөр (CMS-д claimedRole-той); маркерын rev
		// буруу; маркерын docId ≠ verify хуудасных; маркер + QR-гүй тамганы content; 44 pt (QR модуль < 1 pt).
		"seal-qr-citizen-cert": vStampRev(t, p, base, p.citizen, "", sealQR),
		"seal-qr-with-role": vStampRev(t, p, base, p.seal, vRole, func(v *core.Visible) {
			v.Seal, v.Role, v.Tamper = true, vRole, &core.VisibleTamper{SealRole: true}
		}),
		"seal-qr-wrong-rev": vStampRev(t, p, base, p.seal, "", func(v *core.Visible) { v.Seal, v.URL = true, pageVerifyURL+docID+"/3" }),
		"seal-qr-docid-vs-page": vStampRev(t, p, base, p.seal, "", func(v *core.Visible) {
			v.Seal, v.URL = true, pageVerifyURL+"0f1e2d3c-4b5a-4968-8776-5a4b3c2d1e0f/2"
		}),
		"seal-v12-with-marker": vStampRev(t, p, base, p.seal, "", func(v *core.Visible) {
			v.Seal, v.URL, v.Tamper = true, "", &core.VisibleTamper{Body: vFormContent("", func(c []byte) []byte {
				return append(append([]byte("/EIDVerify <</URL ("+url+")>> BDC\n"), c...), "EMC\n"...)
			})}
		}),
		"seal-qr-height-44pt": vStampRev(t, p, base, p.seal, "", func(v *core.Visible) {
			v.Seal, v.H, v.Tamper = true, 4400, &core.VisibleTamper{NoMinModule: true}
		}),
		"seal-qr-control": vStampRev(t, p, base, p.seal, "", sealQR),
		"seal-marker-not-at-start": vStampRev(t, p, base, p.seal, "", func(v *core.Visible) {
			v.Seal, v.URL, v.Tamper = true, "", &core.VisibleTamper{Body: vFormContent("", func(c []byte) []byte {
				i := bytes.IndexByte(c, '\n') + 1
				return append(append(append([]byte{}, c[:i]...), "/EIDVerify <</URL ("+url+")>> BDC\n"...), c[i:]...)
			})}
		}),
		"seal-qr-flate": vStampRev(t, p, base, p.seal, "", func(v *core.Visible) {
			v.Seal, v.Tamper = true, &core.VisibleTamper{Body: vFormContent(" /Filter /FlateDecode", func(c []byte) []byte {
				var z bytes.Buffer
				w := zlib.NewWriter(&z)
				_, _ = w.Write(c)
				_ = w.Close()
				return z.Bytes()
			})}
		}),
		"seal-qr-marker-crlf": vStampRev(t, p, base, p.seal, "", func(v *core.Visible) {
			v.Seal, v.Tamper = true, &core.VisibleTamper{Body: vFormContent("", func(c []byte) []byte {
				return bytes.Replace(c, []byte(")>> BDC\n"), []byte(")>> BDC\r\n"), 1)
			})}
		}),
		// Том үсгийн uuid — verify хуудасгүй сууриар (хуудасны docId-тай тулгалт биш, зөвхөн маркерын дүрэм унагана);
		// хяналт seal-qr-control-nopage нь ижил суурь, жижиг үсэг.
		"seal-qr-control-nopage": vStampRev(t, p, noPage, p.seal, "", sealQR),
		"seal-qr-uuid-uppercase": vStampRev(t, p, noPage, p.seal, "", func(v *core.Visible) {
			v.Seal, v.URL = true, pageVerifyURL+strings.ToUpper(vNoPageDocID)+"/2"
		}),
		"seal-qr-rev-02": vStampRev(t, p, base, p.seal, "", func(v *core.Visible) { v.Seal, v.URL = true, pageVerifyURL+docID+"/02" }),
	}
}

// vRole — сөрөг векторын claimedRole (CMS signer-attributes-v2).
const vRole = "Захирал, Тест ХХК (NTRMN-1234567)"

// vNoPageDocID — golden quartz-pdf13-nopage-ийн docId (баримтад бичигдээгүй; verify хуудасгүй суурийн маркерт).
const vNoPageDocID = "4e5f6071-8293-4a4b-8bce-3f4a5b6c7d8e"

// vMismatchedStamp — base-д signer-ийн 2 дахь гарын үсгийг (B-B) нэмнэ; дардасны хувилбар = seal (QR-гүй тамга, §6.2)
// эсвэл иргэний (§3) — гэрчилгээнээс үл хамааран (Prepare-ийн зам үүнийг хэзээ ч гаргахгүй).
func vMismatchedStamp(t *testing.T, p *goldenPKI, base []byte, signer *gCert, seal bool) []byte {
	t.Helper()
	return vStampRev(t, p, base, signer, "", func(v *core.Visible) {
		if v.Seal = seal; seal {
			v.URL = ""
		}
	})
}

// vFormContent — form XObject-ийн content stream-ийг f-ээр сольж /Length-ийг шинэчилнэ, /Length-ийн ард extra-г
// (жишээ нь « /Filter /FlateDecode») оруулна (VisibleTamper.Body).
func vFormContent(extra string, f func([]byte) []byte) func(string, []byte) []byte {
	length := regexp.MustCompile(`^<< /Length \d+`)
	return func(role string, b []byte) []byte {
		if role != "form" {
			return b
		}
		i, j := bytes.Index(b, []byte(">>\nstream\n")), bytes.LastIndex(b, []byte("\nendstream"))
		if i < 0 || j < i {
			panic("form: stream алга")
		}
		c := f(bytes.Clone(b[i+len(">>\nstream\n") : j]))
		out := length.ReplaceAll(bytes.Clone(b[:i]), fmt.Appendf(nil, "<< /Length %d%s", len(c), extra))
		out = append(append(out, ">>\nstream\n"...), c...)
		return append(out, "\nendstream"...)
	}
}

// vStampRev — base-д signer-ийн 2 дахь гарын үсгийг (B-B: timestamp, DSS-гүй) 1-р хуудсанд 340, 36, 220 × 64 pt
// дардастай нэмнэ. Анхдагч дардас = иргэний (URL = verify хуудасны docId, rev 2); edit нь түүнийг өөрчилнө. role —
// CMS-ийн claimedRole.
func vStampRev(t *testing.T, p *goldenPKI, base []byte, signer *gCert, role string, edit func(*core.Visible)) []byte {
	t.Helper()
	docID := docIDFromPage(base)
	if docID == "" {
		docID = vNoPageDocID // verify хуудасгүй суурь (golden quartz-pdf13-nopage)
	}
	name := core.SignerDisplayName(signer.cert)
	at := goldenTime.In(signingZone)
	vis := core.Visible{Page: 1, X: 34000, Y: 3600, W: 22000, H: 6400, Name: name, Lang: "mn",
		Date: at.Format("2006-01-02 15:04") + " (+08)", URL: pageVerifyURL + docID + "/2"}
	edit(&vis)
	prep, err := core.PrepareSignatureVisible(base, at, name, "", vis)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := core.SignedAttributesWithRole(prep.Digest, signer.cert, role)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(nil, signer.key, crypto.SHA256, core.DTBS(attrs))
	if err != nil {
		t.Fatal(err)
	}
	cms, err := core.AssembleCMS(attrs, signer.cert, []*x509.Certificate{p.ca04.cert, p.ca03.cert, p.ca02.cert}, sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := core.EmbedCMS(prep.PDF, prep.ByteRange, cms)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
