package pades

import (
	"bytes"
	"errors"
	"strings"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// Suggestion — SuggestPlacement's result (PLACEMENT_SPEC.md §6b). Page, X, Y, Width, Height and Status are exactly
// what Prepare returns in Prepared.Placement for the same PDF and Appearance. PageWidth/PageHeight = the visible size
// (CropBox, else MediaBox, after /Rotate; pt) of Page; Pages = the visible size of every page in order (index 0 = page
// 1; {0, 0} = a page whose geometry cannot be read — a stamp cannot go there). Coordinates: origin at the visible
// lower-left corner, x right, y up (APPEARANCE_SPEC.md §1) — a top-left UI offset maps as y = PageHeight − top − Height.
type Suggestion struct {
	Page       int        `json:"page"`
	X          float64    `json:"x"`
	Y          float64    `json:"y"`
	Width      float64    `json:"width"`
	Height     float64    `json:"height"`
	Status     string     `json:"status"`
	PageWidth  float64    `json:"pageWidth"`
	PageHeight float64    `json:"pageHeight"`
	PageCount  int        `json:"pageCount"`
	Pages      []PageSize `json:"pages"`
}

// PageSize — a page's visible size in pt (Suggestion.Pages).
type PageSize struct {
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// SuggestPlacement — runs Prepare's placement (page 0 resolution, page scan, candidate search; Appearance.Exact) on pdf
// without signing, so a UI can show the default stamp position, the page sizes, and whether a chosen rect lies over
// content. It needs no certificate and makes no network call.
//
// Checks: size, PDF header/structure, encryption (PDF_TOO_LARGE / PDF_INVALID / PDF_ENCRYPTED) and the appearance
// request (REQUEST_INVALID: values, page > page count, rect outside the page). Not checked here (Prepare does): prior
// signatures (PDF_FOREIGN_SIGNATURE…), and whether the signer's name fits the stamp size. Page 0 skips this document's
// eID verify pages using the docId read from its verify page (PLACEMENT_SPEC.md §1a) — for an unsigned document no page
// is skipped, exactly as in Prepare.
func SuggestPlacement(doc []byte, a Appearance) (Suggestion, error) {
	if len(doc) > MaxInputBytes {
		return Suggestion{}, newErr(CodePDFTooLarge, "PDF 9.75 MB-аас их байна", nil)
	}
	if !bytes.HasPrefix(doc, []byte("%PDF-")) {
		return Suggestion{}, newErr(CodePDFInvalid, "PDF биш эсвэл эвдэрсэн", nil)
	}
	if err := validate.CheckStructure(doc); err != nil {
		return Suggestion{}, newErr(CodePDFInvalid, "PDF-ийн бүтэц хэт гүн эсвэл төвөгтэй", err)
	}
	if err := checkAppearance(PrepareOptions{Appearance: &a}); err != nil {
		return Suggestion{}, err
	}
	if encrypted(doc) {
		return Suggestion{}, newErr(CodePDFEncrypted, "шифрлэгдсэн PDF дэмжигдэхгүй", nil)
	}
	sigs, _, _, err := scanSignatures(doc)
	if err != nil {
		return Suggestion{}, newErr(CodePDFInvalid, "PDF биш эсвэл эвдэрсэн", err)
	}
	verifyURI := ""
	if len(sigs) > 0 {
		if id := docIDFromPage(doc); id != "" {
			verifyURI = pageVerifyURL + id
		}
	}
	aw, ah := appearanceSize(&a)
	w, h := core.Round100(aw), core.Round100(ah)
	s, err := core.SuggestVisible(doc, verifyURI, a.Page, core.Round100(a.X), core.Round100(a.Y), w, h, a.Exact)
	if errors.Is(err, core.ErrAppearance) {
		return Suggestion{}, newErr(CodeRequestInvalid, "appearance: "+strings.TrimPrefix(err.Error(), "pades: "), err)
	}
	if err != nil {
		return Suggestion{}, newErr(CodePDFInvalid, "PDF задарсангүй", err)
	}
	out := Suggestion{Page: s.Page, X: float64(s.Placement.X) / 100, Y: float64(s.Placement.Y) / 100,
		Width: float64(w) / 100, Height: float64(h) / 100, Status: string(s.Placement.Status), PageCount: len(s.Pages),
		Pages: make([]PageSize, len(s.Pages))}
	for i, p := range s.Pages {
		out.Pages[i] = PageSize{Width: float64(p.W) / 100, Height: float64(p.H) / 100}
	}
	out.PageWidth, out.PageHeight = out.Pages[s.Page-1].Width, out.Pages[s.Page-1].Height
	return out, nil
}
