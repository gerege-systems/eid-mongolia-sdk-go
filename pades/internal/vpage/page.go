package vpage

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/go-pdf/fpdf"

	pades "github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
)

// PAdES баталгаажуулалтын хуудас (docs/PADES_SIGNING.md §7, шийдвэр 10-07 Q9/Q10). Гарын үсэг зурагчийн
// мэдээлэл (нэр, Civil ID, цаг, гарын үсгийн утга) БИЧИХГҮЙ — тэдгээр нь CMS-д бөгөөд хуудас нь зөвхөн эх
// баримтын нэр/hash/хэмжээ, баримтыг нэгтгэх ID + шалгах зам. Эхний гарын үсгийн placeholder-оос ӨМНӨ
// баримтын төгсгөлд нэмэгдэж эхний гарын үсэгт хамрагдана.
//
// Font: Noto Sans (The Noto Project Authors, github.com/notofonts/latin-greek-cyrillic), SIL OFL 1.1
// (fonts/OFL.txt). pyftsubset-ээр (2026-10-07) U+0020–007E, U+00A0–00FF, U+0400–04FF (Өө Үү), U+2010–2027,
// U+2030–203A, U+20AE, U+2116 хүрээнд хассан; нэр, лиценз өөрчлөгдөөгүй. fpdf PDF-д ашигласан glyph-ийг л
// дахин subset хийж embed хийнэ.

//go:embed fonts/NotoSans-Regular.ttf
var notoRegular []byte

//go:embed fonts/NotoSans-Bold.ttf
var notoBold []byte

// DocumentPage — хуудасны агуулга. Хуудас эхний гарын үсгээс ӨМНӨ үүсдэг тул зурагч/гарын үсэг/цагийн
// тэмдгийн мэдээлэл агуулахгүй (тэдгээр нь CMS-д).
type DocumentPage struct {
	Brand        string // "eID Mongolia"
	FileName     string // баримтын нэр (NFC, Кирилл хэвээр)
	DocumentHash string // хуудас нэмэхээс ӨМНӨХ эх PDF-ийн SHA-256 (hex)
	FileSize     int64  // эх PDF-ийн хэмжээ
	DocID        string
	VerifyURL    string // https://ca.eidmongolia.mn/verify/{docID}
	TrustURL     string // Adobe-д үндэсний root-д итгэх заавар
	CAName       string
	TSAName      string
	Provider     string // ca.eidmongolia.mn
	// CreatedAt — хуудасны PDF-ийн /CreationDate /ModDate (SDK: гарын үсгийн цаг — гаралт тодорхойлогдсон байх).
	// Тэг бол fpdf-ийн анхдагч (одоо) — CA-ийн зан.
	CreatedAt time.Time
}

// AppendDocumentPage — гарын үсэггүй баримтын ард хуудсыг INCREMENTAL UPDATE-аар нэмнэ (pades.AppendPage):
// эх баримтын байт яг prefix хэвээр, хэрэглэгчийн ямар ч объект хаягдахгүй.
func AppendDocumentPage(original []byte, p DocumentPage) ([]byte, error) {
	page, err := BuildDocumentPage(p)
	if err != nil {
		return nil, fmt.Errorf("баталгаажуулалтын хуудас: %w", err)
	}
	out, err := pades.AppendPage(original, page)
	if err != nil {
		return nil, fmt.Errorf("хуудас нэмэх: %w", err)
	}
	return out, nil
}

// BuildDocumentPage — нэг A4 хуудас; web-sign-ийн баталгаажуулалтын хуудастай ижил төрх (pdf.go туслахууд),
// Кирилл-д embedded Noto Sans.
func BuildDocumentPage(p DocumentPage) ([]byte, error) {
	if p.DocID == "" || p.VerifyURL == "" || p.DocumentHash == "" {
		return nil, errors.New("docID / verify URL / hash хоосон")
	}
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetCompression(true)
	if !p.CreatedAt.IsZero() {
		pdf.SetCreationDate(p.CreatedAt)
		pdf.SetModificationDate(p.CreatedAt)
	}
	pdf.SetMargins(vpLeft, 15, vpLeft)
	pdf.SetAutoPageBreak(false, 15)
	pdf.AddUTF8FontFromBytes("NotoSans", "", notoRegular)
	pdf.AddUTF8FontFromBytes("NotoSans", "B", notoBold)
	pdf.SetTitle(p.Brand+" — verification page", true)
	pdf.AddPage()
	v := verificationPage{pdf: pdf, sans: "NotoSans"}

	v.banner(p.Brand+" — Electronically signed document",
		"Signatures are embedded in this PDF. Verify them with the link below or in Adobe Acrobat's Signatures panel.")

	v.section("DOCUMENT")
	v.field("File Name", p.FileName)
	v.twoCol("Hash Algorithm", "SHA256", "Size", humanSize(p.FileSize))
	v.mono("Document Hash", p.DocumentHash)
	v.mono("Document ID", p.DocID)

	v.verification(p.VerifyURL, p.TrustURL)

	v.footer(fmt.Sprintf("CA: %s  |  TSA: %s  |  Provider: %s", p.CAName, p.TSAName, p.Provider))

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
