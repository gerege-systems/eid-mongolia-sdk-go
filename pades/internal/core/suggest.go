package core

import (
	"fmt"

	"github.com/digitorus/pdf"
)

// PageSize — a page's visible size (CropBox, else MediaBox, after /Rotate), h100. OK = false when the page geometry
// cannot be read (no usable box, /Rotate not a multiple of 90) — a stamp cannot go on that page.
type PageSize struct {
	W, H int
	OK   bool
}

// Suggestion — SuggestVisible's result: the resolved page (1-based), the placement Prepare would choose there, and the
// visible size of every page in /Pages tree order.
type Suggestion struct {
	Page      int
	Placement Placement
	Pages     []PageSize
}

// SuggestVisible — the placement PrepareSignatureVisible would choose (PLACEMENT_SPEC.md §6, §6b) without writing
// anything. page 0 = DefaultStampPage(doc, verifyURI) (verifyURI "" = no verify pages to skip → the last page); x, y,
// w, h in h100. The rect must lie inside the page (ErrAppearance otherwise), exactly as for Prepare.
func SuggestVisible(doc []byte, verifyURI string, page, x, y, w, h int, exact bool) (s Suggestion, err error) {
	defer func() {
		if r := recover(); r != nil {
			s, err = Suggestion{}, fmt.Errorf("%w: %v", ErrPDF, r)
		}
	}()
	inc, err := openIncremental(doc)
	if err != nil {
		return Suggestion{}, err
	}
	pages := pageList(inc.root().Key("Pages"))
	n := len(pages)
	if page == 0 {
		page = n
		for i := n - 1; verifyURI != "" && i >= 0; i-- {
			if !isVerifyPage(pages[i], verifyURI) {
				page = i + 1
				break
			}
		}
	}
	if page < 1 || page > n {
		return Suggestion{}, fmt.Errorf("%w: page %d > хуудасны тоо %d", ErrAppearance, page, n)
	}
	s.Page = page
	s.Pages = make([]PageSize, n)
	for i, p := range pages {
		if box, rot, err := pageGeometry(p); err == nil {
			vw, vh := box[2]-box[0], box[3]-box[1]
			if rot == 90 || rot == 270 {
				vw, vh = vh, vw
			}
			s.Pages[i] = PageSize{W: vw, H: vh, OK: true}
		}
	}
	box, rot, err := pageGeometry(pages[page-1])
	if err != nil {
		return Suggestion{}, err
	}
	if _, err := VisibleRect(box, rot, x, y, w, h); err != nil {
		return Suggestion{}, err
	}
	s.Placement = PlaceOnPage(pages[page-1], box, rot, x, y, w, h, exact)
	return s, nil
}

// pageList — the /Page objects in /Pages tree order (depth ≤ 32, at most 65 537 — as PageCount / DefaultStampPage).
func pageList(root pdf.Value) []pdf.Value {
	var pages []pdf.Value
	var walk func(v pdf.Value, depth int)
	walk = func(v pdf.Value, depth int) {
		if depth > maxSerializeDepth || len(pages) > 1<<16 {
			return
		}
		switch v.Key("Type").Name() {
		case "Page":
			pages = append(pages, v)
		case "Pages":
			kids := v.Key("Kids")
			for i := range kids.Len() {
				walk(kids.Index(i), depth+1)
			}
		}
	}
	walk(root, 0)
	return pages
}
