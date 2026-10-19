package core

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/digitorus/pdf"
)

// PlaceholderBytes — /Contents-ийн тогтмол багтаамж (binary CMS байт; файлд 2× hex тэмдэгт). Тогтмол нь
// ByteRange-ийг prepare-д тодорхой болгоно — finalize-д дахин хэмжээлэх боломжгүй (digest зурагдсан).
//
// Хэмжилт (2026-10-07, placeholder_test.go TestPlaceholderMeasuredWithOpenSSLTSA): RSA-4096 иргэний cert
// (1603 B) + бодит pki/chain 04/03/02 + прод TSA-ийн тохиргоотой `openssl ts -reply` (timeserver-mn tsa.cnf,
// RSA-3072 TSA cert 1417 B, certs = 04+03+02) token 7001 B → CMS 14226 B; KiB-ээр дээш = MeasuredMaxCMS.
// Шийдвэр 10-07 (§15 Q3): placeholder = хэмжсэн дээд × 2. Runtime-д CMS багтахгүй бол ErrPlaceholderOverflow
// (тайрахгүй, fail-closed).
const (
	MeasuredMaxCMS   = 14 << 10
	PlaceholderBytes = 2 * MeasuredMaxCMS
)

// ErrPlaceholderOverflow — CMS placeholder-т багтсангүй (FAILED PLACEHOLDER_OVERFLOW; иргэн шинээр зурна).
var ErrPlaceholderOverflow = errors.New("pades: CMS placeholder-т багтсангүй")

var (
	oidGivenName = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSurname   = asn1.ObjectIdentifier{2, 5, 4, 4}
)

// SubFilter — манай иргэний гарын үсгийн SubFilter (PAdES baseline).
const SubFilter = "ETSI.CAdES.detached"

// byteRangeWidth — "/ByteRange " дараах тогтмол өргөнтэй талбар ("[0 a b c]" + зай).
const byteRangeWidth = 40

// Prepared — гарын үсгийн revision бичигдсэн, /Contents хоосон (тэг) баримт.
type Prepared struct {
	PDF []byte
	// ByteRange — [0, a, b, c]: a = '<'-ийн байрлал, b = '>'-ийн дараах байрлал, c = төгсгөл хүртэл.
	ByteRange [4]int64
	// Digest — SHA-256(PDF[0:a] ‖ PDF[b:b+c]) — CMS-ийн messageDigest.
	Digest []byte
	// FieldName — шинэ талбарын /T ("Signature k").
	FieldName string
	// Placement — the visible stamp's final position (nil for an invisible signature).
	Placement *Placement
}

// Placement — the stamp's lower-left corner in visible page space (h100) and how it was chosen (PLACEMENT_SPEC.md).
type Placement struct {
	X, Y   int
	Status PlaceStatus
}

// PrepareSignature — base-ийн ард үл харагдах approval гарын үсгийн revision (Sig толь + placeholder,
// widget/талбар, widget-ийг эхний хуудасны /Annots-д нэмсэн хуудас (эсвэл түүний шууд бус /Annots массив),
// шинэ Catalog + AcroForm) бичнэ (§4.1 R_sig). signingTime → /M (мэдүүлсэн цаг). signerName (хоосон биш
// бол) → /Name: 2026-10-13-аас өмнөх иргэний гэрчилгээнд CN байхгүй тул viewer-үүд (Adobe) «Signed by Unknown»
// гэж харуулдаг (шинэ cert-д CN бий ч /Name-ийг хэвээр бичнэ).
func PrepareSignature(base []byte, signingTime time.Time, signerName string) (*Prepared, error) {
	return PrepareSignatureWithReason(base, signingTime, signerName, "")
}

// PrepareSignatureWithReason — PrepareSignature + /Reason (хоосон биш бол; байгууллагын нэрийн өмнөөс гарын үсэгт
// «<байгууллага>-ийг төлөөлж»). Урт нь ReasonMaxUnits-ээс хэтэрвэл /Reason бичихгүй — дуудагч өөрөө богиносгоно.
func PrepareSignatureWithReason(base []byte, signingTime time.Time, signerName, reason string) (*Prepared, error) {
	return prepareSignature(base, signingTime, signerName, reason, nil)
}

// PrepareSignatureVisible — PrepareSignatureWithReason + харагдах widget (APPEARANCE_SPEC.md): /Rect нь vis.Page
// хуудсан дээр, /F 4, /AP /N form XObject (+ 2 фонт), widget тэр хуудасны /Annots-д. vis.Name нь /Name-тэй ижил
// (бичигдэх ёстой — эс бөгөөс ErrAppearance).
func PrepareSignatureVisible(base []byte, signingTime time.Time, signerName, reason string, vis Visible) (*Prepared, error) {
	return prepareSignature(base, signingTime, signerName, reason, &vis)
}

func prepareSignature(base []byte, signingTime time.Time, signerName, reason string, vis *Visible) (out *Prepared, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%w: %v", ErrPDF, r)
		}
	}()
	inc, err := openIncremental(base)
	if err != nil {
		return nil, err
	}
	root := inc.root()
	acro := root.Key("AcroForm")
	fields := acro.Key("Fields")
	names := map[string]bool{}
	sigFields := 0
	for i := range fields.Len() {
		f := fields.Index(i)
		names[f.Key("T").Text()] = true
		if f.Key("FT").Name() == "Sig" {
			sigFields++
		}
	}
	k := sigFields + 1
	for names["Signature "+strconv.Itoa(k)] {
		k++
	}
	fieldName := "Signature " + strconv.Itoa(k)

	sigID, fieldID, catID := inc.reserve(), inc.reserve(), inc.reserve()
	var apIDs [11]uint32 // харагдах: form, F1 ×5, F2 ×5
	if vis != nil {
		for i := range apIDs {
			apIDs[i] = inc.reserve()
		}
	}

	// ── Sig толь (placeholder) ──
	var sig bytes.Buffer
	sig.WriteString("<<\n /Type /Sig\n /Filter /Adobe.PPKLite\n /SubFilter /" + SubFilter + "\n /ByteRange ")
	brAt := sig.Len()
	sig.WriteString(strings.Repeat(" ", byteRangeWidth))
	sig.WriteString("\n /Contents <")
	contentsAt := sig.Len() - 1 // '<'
	sig.Write(bytes.Repeat([]byte("0"), 2*PlaceholderBytes))
	sig.WriteString(">\n /M " + pdfDate(signingTime))
	if n := sigName(signerName); n != "" {
		sig.WriteString("\n /Name " + n)
	}
	if r := sigText(reason, ReasonMaxUnits); r != "" {
		sig.WriteString("\n /Reason " + r)
	}
	sig.WriteString("\n>>")
	sigStart := inc.writeObject(sigID, sig.Bytes())

	// ── Талбар + widget ──
	var page pdf.Value
	var hasPage bool
	var placed *Placement
	if vis == nil {
		// Үл харагдах (digitorus createVisualSignature, invisible): эхний хуудас.
		var fld bytes.Buffer
		fld.WriteString("<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [0 0 0 0]\n")
		page, hasPage = firstPage(root.Key("Pages"), 0)
		if hasPage {
			p := page.GetPtr()
			fmt.Fprintf(&fld, "  /P %d %d R\n", p.GetID(), p.GetGen())
		}
		fmt.Fprintf(&fld, "  /F 132\n  /FT /Sig\n  /T (%s)\n  /V %d 0 R\n>>", fieldName, sigID)
		inc.writeObject(fieldID, fld.Bytes())
	} else {
		if sigName(signerName) == "" || strings.TrimSpace(signerName) != vis.Name {
			return nil, fmt.Errorf("%w: /Name бичигдэхгүй нэр", ErrAppearance)
		}
		if page, hasPage = nthPage(root.Key("Pages"), vis.Page); !hasPage {
			return nil, fmt.Errorf("%w: хуудас %d алга", ErrAppearance, vis.Page)
		}
		box, rot, err := pageGeometry(page)
		if err != nil {
			return nil, err
		}
		rect, err := VisibleRect(box, rot, vis.X, vis.Y, vis.W, vis.H)
		if err != nil {
			return nil, err
		}
		placed = &Placement{X: vis.X, Y: vis.Y, Status: PlaceRequested}
		if vis.Avoid {
			// PLACEMENT_SPEC.md: move off existing page content; the requested rect stays when nothing is free.
			occ, err := Occupancy(page, box)
			switch {
			case err != nil:
				placed.Status = PlaceUnscanned
			default:
				px, py, ok := PlaceVisible(box, rot, vis.X, vis.Y, vis.W, vis.H, occ)
				switch {
				case !ok:
					placed.Status = PlaceOverlap
				case px != vis.X || py != vis.Y:
					placed.X, placed.Y, placed.Status = px, py, PlaceMoved
					if rect, err = VisibleRect(box, rot, px, py, vis.W, vis.H); err != nil {
						return nil, err
					}
				}
			}
		}
		bodies, err := AppearanceObjects(AppearanceParams{W: vis.W, H: vis.H, Rotate: rot, Name: vis.Name, Role: vis.Role,
			Lang: vis.Lang, Date: vis.Date, URL: vis.URL}, apIDs)
		if err != nil {
			return nil, err
		}
		p := page.GetPtr()
		widget := VisibleWidget(fieldName, rect, p.GetID(), int(p.GetGen()), sigID, apIDs[0])
		if tm := vis.Tamper; tm != nil && tm.Body != nil {
			widget = tm.Body("widget", widget)
			for i := range bodies {
				role := "form"
				if i > 0 {
					role = fmt.Sprintf("F%d.%d", (i-1)/5+1, (i-1)%5)
				}
				bodies[i] = tm.Body(role, bodies[i])
			}
		}
		inc.writeObject(fieldID, widget)
		for i, b := range bodies {
			inc.writeObject(apIDs[i], b)
		}
		if tm := vis.Tamper; tm != nil {
			for _, id := range slices.Sorted(maps.Keys(tm.Extra)) {
				inc.writeObject(id, tm.Extra[id])
			}
		}
		if tm := vis.Tamper; tm != nil && tm.AnnotsPage != 0 {
			if hasPage = tm.AnnotsPage > 0; hasPage {
				page, _ = nthPage(root.Key("Pages"), tm.AnnotsPage)
			}
		}
	}
	// Widget нь annotation тул хуудасны /Annots-д заавал орно (ISO 32000-1 §12.5.2; эс бөгөөс Adobe/pyHanko
	// талбарыг хуудасгүй гэж үзнэ).
	if hasPage {
		if err := addWidgetToPage(inc, page, fieldID); err != nil {
			return nil, err
		}
	}

	// ── Шинэ Catalog ──
	var cat bytes.Buffer
	cat.WriteString("<<\n  /Type /Catalog\n")
	if root.Key("Version").IsNull() {
		if v, err := strconv.ParseFloat(inc.rdr.PDFVersion, 64); err == nil && v < 1.5 {
			cat.WriteString("  /Version /1.5\n")
		}
	}
	if err := inc.catalogCopy(&cat, "AcroForm"); err != nil {
		return nil, err
	}
	cat.WriteString("  /AcroForm <<")
	if acro.Kind() == pdf.Dict {
		ap := acro.GetPtr()
		for _, key := range acro.Keys() {
			if key == "Fields" || key == "SigFlags" {
				continue
			}
			cat.WriteString(" /" + escapeName(key) + " ")
			if err := serialize(&cat, acro.Key(key), ap.GetID(), 0); err != nil {
				return nil, fmt.Errorf("AcroForm /%s: %w", key, err)
			}
		}
	}
	cat.WriteString(" /Fields [")
	fp := fields.GetPtr()
	for i := range fields.Len() {
		if err := serialize(&cat, fields.Index(i), fp.GetID(), 0); err != nil {
			return nil, fmt.Errorf("AcroForm /Fields: %w", err)
		}
		cat.WriteString(" ")
	}
	fmt.Fprintf(&cat, "%d 0 R] /SigFlags 3 >>\n>>", fieldID)
	inc.writeObject(catID, cat.Bytes())

	doc, err := inc.finish(catID)
	if err != nil {
		return nil, err
	}
	// ByteRange: '<' хүртэл, '>'-ийн дараахаас төгсгөл хүртэл.
	a := sigStart + int64(contentsAt)
	b := a + 2*PlaceholderBytes + 2
	if doc[a] != '<' || doc[b-1] != '>' {
		return nil, errors.New("pades: placeholder-ийн байрлал буруу")
	}
	br := [4]int64{0, a, b, int64(len(doc)) - b}
	field := fmt.Sprintf("[%d %d %d %d]", br[0], br[1], br[2], br[3])
	if len(field) > byteRangeWidth {
		return nil, errors.New("pades: ByteRange талбарт багтсангүй")
	}
	copy(doc[sigStart+int64(brAt):], field)
	h := sha256.New()
	h.Write(doc[:a])
	h.Write(doc[b:])
	return &Prepared{PDF: doc, ByteRange: br, Digest: h.Sum(nil), FieldName: fieldName, Placement: placed}, nil
}

// EmbedCMS — prepared баримтын placeholder-т CMS-ийг hex-ээр бичнэ (бусад байт өөрчлөгдөхгүй). CMS
// багтахгүй бол ErrPlaceholderOverflow — хэзээ ч тайрахгүй.
func EmbedCMS(prepared []byte, br [4]int64, cms []byte) ([]byte, error) {
	if len(cms) == 0 {
		return nil, errors.New("pades: CMS хоосон")
	}
	if len(cms) > PlaceholderBytes {
		return nil, fmt.Errorf("%w: %d > %d байт", ErrPlaceholderOverflow, len(cms), PlaceholderBytes)
	}
	a, b := br[1], br[2]
	if br[0] != 0 || a <= 0 || b != a+2*PlaceholderBytes+2 || b+br[3] != int64(len(prepared)) ||
		prepared[a] != '<' || prepared[b-1] != '>' {
		return nil, errors.New("pades: ByteRange нь prepared баримттай таарахгүй")
	}
	if strings.Trim(string(prepared[a+1:b-1]), "0") != "" {
		return nil, errors.New("pades: placeholder аль хэдийн бөглөгдсөн")
	}
	out := bytes.Clone(prepared)
	hex.Encode(out[a+1:], cms)
	return out, nil
}

// SignatureContents — signed-ийн ByteRange-ийн заасан /Contents утга: hex тайлсан, placeholder-ийн тэг
// дүүргэлтийг оруулаад (viewer-ийн уншдаг string-ийн байт) — DSS.Contents-д (VRI түлхүүр).
func SignatureContents(signed []byte, br [4]int64) ([]byte, error) {
	a, b := br[1], br[2]
	if br[0] != 0 || a <= 0 || b <= a+2 || b > int64(len(signed)) || signed[a] != '<' || signed[b-1] != '>' {
		return nil, errors.New("pades: ByteRange нь /Contents-ийг заахгүй")
	}
	out := make([]byte, (b-a-2)/2)
	if _, err := hex.Decode(out, signed[a+1:b-1]); err != nil {
		return nil, fmt.Errorf("pades: /Contents hex: %w", err)
	}
	return out, nil
}

// addWidgetToPage — хуудасны /Annots-ийн төгсгөлд widget-ийг нэмнэ: /Annots шууд бус массив бол тэр массивыг,
// эс бөгөөс хуудсыг (ижил дугаар, бусад түлхүүр хэвээр) шинэ хувилбараар бичнэ.
func addWidgetToPage(inc *incremental, page pdf.Value, widget uint32) error {
	pgp := page.GetPtr()
	annots := page.Key("Annots")
	if !annots.IsNull() && annots.Kind() != pdf.Array {
		return fmt.Errorf("%w: хуудасны /Annots массив биш", ErrPDF)
	}
	ap := annots.GetPtr()
	var arr bytes.Buffer
	arr.WriteString("[")
	for i := range annots.Len() {
		if err := serialize(&arr, annots.Index(i), ap.GetID(), 0); err != nil {
			return fmt.Errorf("хуудасны /Annots: %w", err)
		}
		arr.WriteString(" ")
	}
	fmt.Fprintf(&arr, "%d 0 R]", widget)
	if !annots.IsNull() && ap != pgp {
		inc.writeObjectGen(ap.GetID(), uint16(ap.GetGen()), arr.Bytes())
		return nil
	}
	var b bytes.Buffer
	b.WriteString("<<")
	for _, key := range page.Keys() {
		if key == "Annots" {
			continue
		}
		b.WriteString(" /" + escapeName(key) + " ")
		if err := serialize(&b, page.Key(key), pgp.GetID(), 0); err != nil {
			return fmt.Errorf("хуудас /%s: %w", key, err)
		}
	}
	b.WriteString(" /Annots ")
	b.Write(arr.Bytes())
	b.WriteString(" >>")
	inc.writeObjectGen(pgp.GetID(), uint16(pgp.GetGen()), b.Bytes())
	return nil
}

// sigName — /Name-ийн PDF text string (hex): ASCII бол шууд, эс бөгөөс BOM-той UTF-16BE. Удирдах тэмдэгт,
// 120 тэмдэгтээс урт эсвэл хоосон бол "" (бичихгүй — validator-ийн ownText-ийн хүрээнд).
func sigName(s string) string { return sigText(s, 120) }

// ReasonMaxUnits — /Reason-ийн дээд урт UTF-16 нэгжээр: BOM (2 байт) + 2×127 = 256 байт = нийтийн шалгагчийн
// ownTextLimit (internal/validate/revisions.go).
const ReasonMaxUnits = 127

// sigText — sigName-ийн ерөнхий хэлбэр: maxUnits — UTF-16 нэгжийн дээд тоо (BMP-д тэмдэгтийн тоо).
func sigText(s string, maxUnits int) string {
	s = strings.TrimSpace(s)
	if s == "" || !utf8.ValidString(s) || len(utf16.Encode([]rune(s))) > maxUnits {
		return ""
	}
	ascii := true
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return ""
		}
		if r > 0x7e {
			ascii = false
		}
	}
	if strings.Contains(s, " obj") || strings.Contains(s, "endobj") || strings.Contains(s, "stream") ||
		strings.Contains(s, "xref") || strings.Contains(s, "trailer") || strings.Contains(s, "%%EOF") {
		return ""
	}
	if ascii {
		return hexString(s)
	}
	var raw []byte
	raw = append(raw, 0xfe, 0xff)
	for _, u := range utf16.Encode([]rune(s)) {
		raw = binary.BigEndian.AppendUint16(raw, u)
	}
	return hexString(string(raw))
}

// SignerDisplayName — гэрчилгээний GIVENNAME SURNAME (cert-д бичигдсэнээрээ, Латин); байхгүй бол CN.
func SignerDisplayName(cert *x509.Certificate) string {
	var given, sur string
	for _, n := range cert.Subject.Names {
		v, _ := n.Value.(string)
		switch {
		case n.Type.Equal(oidGivenName):
			given = v
		case n.Type.Equal(oidSurname):
			sur = v
		}
	}
	if name := strings.TrimSpace(given + " " + sur); name != "" {
		return name
	}
	return cert.Subject.CommonName
}

// firstPage — /Pages модноос эхний /Page (digitorus findFirstPage; гүнийг хязгаарласан).
func firstPage(v pdf.Value, depth int) (pdf.Value, bool) {
	if depth > maxSerializeDepth {
		return pdf.Value{}, false
	}
	switch v.Key("Type").Name() {
	case "Page":
		return v, true
	case "Pages":
		kids := v.Key("Kids")
		for i := range kids.Len() {
			if p, ok := firstPage(kids.Index(i), depth+1); ok {
				return p, true
			}
		}
	}
	return pdf.Value{}, false
}

// pdfDate — "(D:YYYYMMDDHHmmSS+HH'mm')" (digitorus pdfDateTime; validator ownDate).
func pdfDate(t time.Time) string {
	_, off := t.Zone()
	sign := '+'
	if off < 0 {
		sign, off = '-', -off
	}
	return fmt.Sprintf("(D:%s%c%02d'%02d')", t.Format("20060102150405"), sign, off/3600, (off%3600)/60)
}
