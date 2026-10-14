// Package pdfsign — PAdES (горим A, docs/PADES_SIGNING.md)-ийн PDF туслахууд: баталгаажуулалтын хуудас
// (page.go), гарын үсэг мэт объектын скан, RFC3161 TSA клиент/итгэл (tsa.go, pkcs7.go). Платформын doc-signer-ээр
// PKCS#7 embed хийдэг хуучин web-sign stamp (`POST /v3/signature/stamp`) 2026-10-13-нд устсан; түүний гаргасан
// файлыг шалгах нь validate багцад (pdf_stamps, doc-signer профайл).
package vpage

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/digitorus/pdf"
	"github.com/go-pdf/fpdf"
	qrcode "github.com/skip2/go-qrcode"
)

// HasSignatureObjects — баримтад гарын үсэг МЭТ харагдах (/ByteRange + /Contents-тэй) объект байгаа эсэх.
// Энэ нь итгэлийн шийдвэр биш: true нь «гарын үсэг хүчинтэй» гэсэн үг биш (хуурамч объект ч true өгнө).
func HasSignatureObjects(doc []byte) (found bool, err error) {
	// digitorus/pdf нь эвдэрсэн объект дээр panic хийдэг — алдаа болгож буцаана.
	defer func() {
		if recover() != nil {
			found, err = false, errors.New("PDF parse: эвдэрсэн PDF")
		}
	}()
	reader, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		return false, fmt.Errorf("PDF parse: %w", err)
	}
	for _, ref := range reader.Xref() {
		value := reader.Resolve(ref.Ptr(), ref.Ptr())
		if !value.Key("ByteRange").IsNull() && !value.Key("Contents").IsNull() {
			return true, nil
		}
	}
	return false, nil
}

// Баталгаажуулалтын хуудасны нийтлэг өнгө, хэмжээ — PAdES-ийн гарын үсгээс өмнөх хуудас (BuildDocumentPage).
const (
	vpLeft  = 15.0
	vpWidth = 180.0
	vpColW  = 90.0

	vpTextR, vpTextG, vpTextB    = 30, 30, 30
	vpMutedR, vpMutedG, vpMutedB = 110, 110, 110
	vpOKR, vpOKG, vpOKB          = 22, 138, 79
	vpOKBgR, vpOKBgG, vpOKBgB    = 220, 245, 230
	vpLineR, vpLineG, vpLineB    = 220, 220, 220
	vpLinkR, vpLinkG, vpLinkB    = 30, 110, 220
)

// verificationPage — хуудасны зурах туслахууд. sans нь утгын font (Helvetica эсвэл Кирилл-д NotoSans); hash/ID-д
// Courier (ASCII).
type verificationPage struct {
	pdf  *fpdf.Fpdf
	sans string
}

func (p verificationPage) banner(title, subtitle string) {
	pdf := p.pdf
	pdf.SetFillColor(vpOKBgR, vpOKBgG, vpOKBgB)
	pdf.RoundedRect(vpLeft, 15, vpWidth, 18, 2, "1234", "F")
	pdf.SetTextColor(vpOKR, vpOKG, vpOKB)
	pdf.SetFont(p.sans, "B", 13)
	pdf.SetXY(20, 19)
	pdf.Cell(0, 6, title)
	pdf.SetFont(p.sans, "", 9)
	pdf.SetXY(20, 26)
	pdf.Cell(0, 4, subtitle)
	pdf.SetTextColor(vpTextR, vpTextG, vpTextB)
	pdf.Ln(20)
}

func (p verificationPage) section(title string) {
	pdf := p.pdf
	pdf.Ln(4)
	pdf.SetDrawColor(vpLineR, vpLineG, vpLineB)
	pdf.Line(vpLeft, pdf.GetY(), vpLeft+vpWidth, pdf.GetY())
	pdf.Ln(2)
	pdf.SetFont(p.sans, "B", 11)
	pdf.SetTextColor(vpTextR, vpTextG, vpTextB)
	pdf.CellFormat(0, 6, title, "", 1, "L", false, 0, "")
	pdf.Ln(1)
}

func (p verificationPage) label(text string) {
	p.pdf.SetFont(p.sans, "", 8)
	p.pdf.SetTextColor(vpMutedR, vpMutedG, vpMutedB)
	p.pdf.CellFormat(0, 4, strings.ToUpper(text), "", 1, "L", false, 0, "")
}

func (p verificationPage) twoCol(label1, value1, label2, value2 string) {
	pdf := p.pdf
	startY := pdf.GetY()
	pdf.SetFont(p.sans, "", 8)
	pdf.SetTextColor(vpMutedR, vpMutedG, vpMutedB)
	pdf.SetXY(vpLeft, startY)
	pdf.CellFormat(vpColW, 4, strings.ToUpper(label1), "", 0, "L", false, 0, "")
	pdf.SetXY(vpLeft+vpColW, startY)
	pdf.CellFormat(vpColW, 4, strings.ToUpper(label2), "", 1, "L", false, 0, "")

	pdf.SetFont(p.sans, "B", 10)
	pdf.SetTextColor(vpTextR, vpTextG, vpTextB)
	pdf.SetXY(vpLeft, pdf.GetY())
	pdf.CellFormat(vpColW, 6, value1, "", 0, "L", false, 0, "")
	pdf.SetXY(vpLeft+vpColW, pdf.GetY())
	pdf.CellFormat(vpColW, 6, value2, "", 1, "L", false, 0, "")
	pdf.Ln(1)
}

// field — бүтэн өргөнтэй (урт утгыг мөр шилжүүлнэ) label/value.
func (p verificationPage) field(label, value string) {
	p.label(label)
	p.pdf.SetFont(p.sans, "B", 10)
	p.pdf.SetTextColor(vpTextR, vpTextG, vpTextB)
	p.pdf.MultiCell(vpWidth, 6, value, "", "L", false)
	p.pdf.Ln(1)
}

func (p verificationPage) mono(label, value string) {
	p.label(label)
	p.pdf.SetFont("Courier", "", 9)
	p.pdf.SetTextColor(vpTextR, vpTextG, vpTextB)
	p.pdf.MultiCell(vpWidth, 5, value, "", "L", false)
	p.pdf.Ln(1)
}

// verification — URL + QR + «Scan to verify»; trustURL (хоосон биш бол) Adobe-д итгэх заавар ижил блокт.
func (p verificationPage) verification(verifyURL, trustURL string) {
	pdf := p.pdf
	p.section("VERIFICATION")
	pdf.SetFont(p.sans, "", 9)
	pdf.SetTextColor(vpLinkR, vpLinkG, vpLinkB)
	pdf.CellFormat(0, 5, verifyURL, "", 1, "L", false, 0, verifyURL)
	pdf.Ln(2)

	qrPNG, err := qrcode.Encode(verifyURL, qrcode.Medium, 240)
	if err != nil {
		return
	}
	pdf.RegisterImageOptionsReader("qr", fpdf.ImageOptions{ImageType: "PNG", ReadDpi: false}, bytes.NewReader(qrPNG))
	yQR := pdf.GetY()
	pdf.ImageOptions("qr", vpLeft, yQR, 28, 28, false, fpdf.ImageOptions{}, 0, "")

	const textX, textW = 48.0, 140.0
	pdf.SetXY(textX, yQR+2)
	pdf.SetFont(p.sans, "B", 11)
	pdf.SetTextColor(vpTextR, vpTextG, vpTextB)
	pdf.CellFormat(0, 5, "Scan to verify", "", 1, "L", false, 0, "")
	pdf.SetXY(textX, pdf.GetY())
	pdf.SetFont(p.sans, "", 9)
	pdf.SetTextColor(vpMutedR, vpMutedG, vpMutedB)
	pdf.MultiCell(textW, 4, "Scan this QR code with your phone camera to verify.", "", "L", false)
	pdf.SetXY(textX, pdf.GetY()+1)
	pdf.SetFont(p.sans, "B", 9)
	pdf.SetTextColor(vpLinkR, vpLinkG, vpLinkB)
	pdf.CellFormat(0, 4, urlHost(verifyURL), "", 1, "L", false, 0, "")
	if trustURL != "" {
		pdf.SetXY(textX, pdf.GetY()+2)
		pdf.SetFont(p.sans, "", 9)
		pdf.SetTextColor(vpMutedR, vpMutedG, vpMutedB)
		pdf.CellFormat(textW, 4, "Adobe Acrobat: trust the Mongolian National Root CA", "", 1, "L", false, 0, "")
		pdf.SetX(textX)
		pdf.SetFont(p.sans, "B", 9)
		pdf.SetTextColor(vpLinkR, vpLinkG, vpLinkB)
		pdf.CellFormat(textW, 4, trustURL, "", 1, "L", false, 0, trustURL)
	}
	pdf.SetY(max(yQR+30, pdf.GetY()+2))
}

func (p verificationPage) footer(text string) {
	pdf := p.pdf
	pdf.SetY(-25)
	pdf.SetDrawColor(vpLineR, vpLineG, vpLineB)
	pdf.Line(vpLeft, pdf.GetY(), vpLeft+vpWidth, pdf.GetY())
	pdf.Ln(2)
	pdf.SetFont(p.sans, "", 8)
	pdf.SetTextColor(vpMutedR, vpMutedG, vpMutedB)
	pdf.CellFormat(0, 4, text, "", 1, "L", false, 0, "")
}

func humanSize(b int64) string {
	const k = 1024.0
	switch {
	case b < int64(k):
		return fmt.Sprintf("%d B", b)
	case b < int64(k*k):
		return fmt.Sprintf("%.1f KB", float64(b)/k)
	case b < int64(k*k*k):
		return fmt.Sprintf("%.1f MB", float64(b)/(k*k))
	default:
		return fmt.Sprintf("%.1f GB", float64(b)/(k*k*k))
	}
}

func urlHost(u string) string {
	s := u
	for _, p := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, p)
	}
	if i := strings.Index(s, "/"); i > 0 {
		next := strings.Index(s[i+1:], "/")
		if next > 0 {
			return s[:i+1+next]
		}
	}
	return s
}
