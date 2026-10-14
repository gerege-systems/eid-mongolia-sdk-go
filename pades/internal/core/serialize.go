package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/digitorus/pdf"
)

const maxSerializeDepth = 32

var errDepth = errors.New("pades: утга хэт гүн давхарласан")

// serialize — digitorus serializeCatalogEntry-ийн fork: container объект доторх ШУУД утгыг дахин бичнэ,
// өөр объект руу заасан утгыг (ptr ≠ container) "N G R" заалтаар үлдээнэ. Ялгаа: мөрийг hex-ээр (escape
// алдаагүй), нэрийг #xx-ээр, бодит тоог exponent-гүй бичнэ; null заалтыг (байхгүй объект) "null".
func serialize(w io.Writer, v pdf.Value, container uint32, depth int) error {
	if depth > maxSerializeDepth {
		return errDepth
	}
	if v.IsNull() {
		_, err := io.WriteString(w, "null")
		return err
	}
	if p := v.GetPtr(); p.GetID() != container {
		_, err := fmt.Fprintf(w, "%d %d R", p.GetID(), p.GetGen())
		return err
	}
	var err error
	switch v.Kind() {
	case pdf.String:
		_, err = io.WriteString(w, hexString(v.RawString()))
	case pdf.Bool:
		_, err = io.WriteString(w, strconv.FormatBool(v.Bool()))
	case pdf.Integer:
		_, err = io.WriteString(w, strconv.FormatInt(v.Int64(), 10))
	case pdf.Real:
		_, err = io.WriteString(w, strconv.FormatFloat(v.Float64(), 'f', -1, 64))
	case pdf.Name:
		_, err = io.WriteString(w, "/"+escapeName(v.Name()))
	case pdf.Dict:
		if _, err = io.WriteString(w, "<<"); err != nil {
			return err
		}
		for _, key := range v.Keys() {
			if _, err = io.WriteString(w, " /"+escapeName(key)+" "); err != nil {
				return err
			}
			if err = serialize(w, v.Key(key), container, depth+1); err != nil {
				return err
			}
		}
		_, err = io.WriteString(w, " >>")
	case pdf.Array:
		if _, err = io.WriteString(w, "["); err != nil {
			return err
		}
		for i := range v.Len() {
			if i > 0 {
				if _, err = io.WriteString(w, " "); err != nil {
					return err
				}
			}
			if err = serialize(w, v.Index(i), container, depth+1); err != nil {
				return err
			}
		}
		_, err = io.WriteString(w, "]")
	default:
		return errors.New("pades: шууд stream (эсвэл танихгүй утга) хуулах боломжгүй")
	}
	return err
}

// hexString — PDF hex string (<...>), байтыг яг хэвээр.
func hexString(raw string) string { return "<" + hex.EncodeToString([]byte(raw)) + ">" }

// escapeName — PDF name-ийн regular-биш тэмдэгтийг #xx болгоно (ISO 32000-1 §7.3.5).
func escapeName(n string) string {
	var b strings.Builder
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c < 0x21 || c > 0x7e || strings.IndexByte("#()<>[]{}/%", c) >= 0 {
			fmt.Fprintf(&b, "#%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
