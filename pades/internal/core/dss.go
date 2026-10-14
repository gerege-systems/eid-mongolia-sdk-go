package core

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- VRI түлхүүр нь ISO 32000-2 §12.8.4.4-ийн дагуу SHA-1 (таних, аюулгүй байдлын биш)
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/digitorus/pdf"
)

// DSS — нэг гарын үсгийн LTV өгөгдөл (DER). Хуучин DSS-ийн stream-тэй байт-ижил зүйлийг дахин бичихгүй
// (заалтаар дахин ашиглана).
type DSS struct {
	Certs, OCSPs, CRLs [][]byte
	// Contents — гарын үсгийн /Contents утга яг viewer-ийн уншдаг байтаар: hex тайлсан, placeholder-ийн тэг
	// дүүргэлттэй (SignatureContents). VRI түлхүүр = SHA1(Contents) том hex (ISO 32000-2 §12.8.4.4; iText,
	// pyHanko ижил). Зөвхөн CMS DER-ийн SHA1 нь өөр түлхүүр болж viewer VRI-г олохгүй. Хоосон бол VRI
	// бичихгүй.
	Contents []byte
}

// maxDSSStream — хуучин DSS stream уншихад дээд хэмжээ.
const maxDSSStream = 4 << 20

// AppendDSS — гарын үсэгтэй баримтын ард /DSS revision (гарын үсэггүй) нэмнэ (§4.1 R_dss, §4.4): хуучин
// DSS-ийн бүх мөрийг хадгалж шинийг нэмсэн шинэ DSS толь + шинэ Catalog.
func AppendDSS(signed []byte, d DSS) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%w: %v", ErrPDF, r)
		}
	}()
	if len(d.Certs)+len(d.OCSPs)+len(d.CRLs) == 0 {
		return nil, errors.New("pades: DSS хоосон")
	}
	inc, err := openIncremental(signed)
	if err != nil {
		return nil, err
	}
	root := inc.root()
	old := root.Key("DSS")
	if !old.IsNull() && old.Kind() != pdf.Dict {
		return nil, fmt.Errorf("%w: /DSS толь биш", ErrPDF)
	}
	// Хуучин stream-ууд: sha256(агуулга) → заалт.
	known := map[[32]byte]string{}
	lists := map[string][]string{}
	for _, key := range []string{"Certs", "OCSPs", "CRLs"} {
		arr := old.Key(key)
		ap := arr.GetPtr()
		for i := range arr.Len() {
			e := arr.Index(i)
			var ref strings.Builder
			if err := serialize(&ref, e, ap.GetID(), 0); err != nil {
				return nil, err
			}
			lists[key] = append(lists[key], ref.String())
			if e.Kind() == pdf.Stream {
				if data, err := io.ReadAll(io.LimitReader(e.Reader(), maxDSSStream)); err == nil {
					known[sha256.Sum256(data)] = ref.String()
				}
			}
		}
	}
	var vriEntry [3][]string // Cert, OCSP, CRL
	add := func(slot int, key string, items [][]byte) {
		for _, der := range items {
			sum := sha256.Sum256(der)
			ref, ok := known[sum]
			if !ok {
				var s bytes.Buffer
				fmt.Fprintf(&s, "<< /Length %d >>\nstream\n", len(der))
				s.Write(der)
				s.WriteString("\nendstream")
				id, _ := inc.addObject(s.Bytes())
				ref = itoa(id) + " 0 R"
				known[sum] = ref
				lists[key] = append(lists[key], ref)
			}
			if !contains(vriEntry[slot], ref) {
				vriEntry[slot] = append(vriEntry[slot], ref)
			}
		}
	}
	add(0, "Certs", d.Certs)
	add(1, "OCSPs", d.OCSPs)
	add(2, "CRLs", d.CRLs)

	var dss bytes.Buffer
	dss.WriteString("<<")
	for _, key := range []string{"Certs", "OCSPs", "CRLs"} {
		if len(lists[key]) > 0 {
			dss.WriteString(" /" + key + " [" + strings.Join(lists[key], " ") + "]")
		}
	}
	vri := old.Key("VRI")
	if len(d.Contents) > 0 || vri.Kind() == pdf.Dict {
		dss.WriteString(" /VRI <<")
		vp := vri.GetPtr()
		var newKey string
		if len(d.Contents) > 0 {
			sum := sha1.Sum(d.Contents) // #nosec G401 -- VRI түлхүүрийн стандарт
			newKey = strings.ToUpper(hex.EncodeToString(sum[:]))
		}
		for _, key := range vri.Keys() {
			if key == newKey {
				continue
			}
			dss.WriteString(" /" + escapeName(key) + " ")
			if err := serialize(&dss, vri.Key(key), vp.GetID(), 0); err != nil {
				return nil, fmt.Errorf("VRI: %w", err)
			}
		}
		if newKey != "" {
			dss.WriteString(" /" + newKey + " <<")
			for i, k := range []string{"Cert", "OCSP", "CRL"} {
				if len(vriEntry[i]) > 0 {
					dss.WriteString(" /" + k + " [" + strings.Join(vriEntry[i], " ") + "]")
				}
			}
			dss.WriteString(" >>")
		}
		dss.WriteString(" >>")
	}
	dss.WriteString(" >>")
	dssID, _ := inc.addObject(dss.Bytes())

	var cat bytes.Buffer
	cat.WriteString("<<\n  /Type /Catalog\n")
	if err := inc.catalogCopy(&cat, "DSS"); err != nil {
		return nil, err
	}
	fmt.Fprintf(&cat, "  /DSS %d 0 R\n>>", dssID)
	catID, _ := inc.addObject(cat.Bytes())
	return inc.finish(catID)
}
