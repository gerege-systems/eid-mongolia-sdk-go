package eid

import (
	"context"
	"errors"
	"testing"
)

// imageJSON — CA dto.ImageResponse (docs/SIGNATURE_IMAGES.md): png, sha256, width, height, updatedAt, pdfImage.
const imageJSON = `{"png":"iVBORw==","sha256":"` + sha64 + `","width":480,"height":144,"updatedAt":"2026-10-23T05:00:00Z",` +
	`"pdfImage":{"width":480,"height":144,"color":[18,32,110],"alpha":"eJwDAAAAAAE=","sha256":"` + sha64 + `"}}`

const sha64 = "ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"

func TestPersonSignatureImage(t *testing.T) {
	ctx := context.Background()
	c, rc := server(t, jsonReply(200, imageJSON))
	img, err := c.Person.SignatureImage(ctx, "PNOMN-12345678")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := rc.last()
	if req.Method != "GET" || req.URL.Path != "/person/etsi/PNOMN-12345678/signature-image" {
		t.Fatalf("хүсэлт %s %s", req.Method, req.URL.Path)
	}
	p := img.PDFImage
	if img.SHA256 != sha64 || img.Width != 480 || string(img.PNG) != "\x89PNG" || p == nil || p.Color != [3]int{18, 32, 110} ||
		p.SHA256 != sha64 || len(p.Alpha) != 8 || img.UpdatedAt == "" {
		t.Fatalf("задаргаа: %+v %+v", img, p)
	}

	c, _ = server(t, jsonReply(404, `{"error":"зураг алга","code":"NOT_FOUND"}`))
	if img, err := c.Person.SignatureImage(ctx, "PNOMN-1"); img != nil || err != nil {
		t.Fatalf("404 → (nil, nil) хүлээсэн: %v %v", img, err)
	}
	c, _ = server(t, jsonReply(403, `{"error":"RP-д SIGN эрх алга"}`))
	var fe *ForbiddenError
	if _, err := c.Person.SignatureImage(ctx, "PNOMN-1"); !errors.As(err, &fe) {
		t.Fatalf("403 → *ForbiddenError: %v", err)
	}
}

func TestRepresentationStampImage(t *testing.T) {
	c, _ := server(t, jsonReply(200, `{"personEtsi":"PNOMN-1","representations":[`+
		`{"orgEtsi":"NTRMN-1","stampImageSet":true,"stampImage":`+imageJSON+`},{"orgEtsi":"NTRMN-2","stampImageSet":false}]}`))
	r, err := c.Organization.GetRepresentations(context.Background(), "PNOMN-1")
	if err != nil {
		t.Fatal(err)
	}
	a, b := r.Representations[0], r.Representations[1]
	if !a.StampImageSet || a.StampImage == nil || a.StampImage.PDFImage == nil || a.StampImage.PDFImage.Width != 480 ||
		b.StampImageSet || b.StampImage != nil {
		t.Fatalf("stampImage: %+v %+v", a, b)
	}
}
