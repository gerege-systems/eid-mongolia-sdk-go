package validate

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

// nameString — pkix.Name.String()-ийн Go 1.26 хүртэлх (CA прод golang:1.26.9) хэлбэр, Go-ийн хувилбараас хамааралгүй:
// Go 1.27 танихгүй төрлийн (GIVENNAME 2.5.4.42, SURNAME 2.5.4.4 …) утгыг «#<DER hex>»-ийн оронд бичвэрээр гаргадаг болсон
// тул тайлангийн subject/issuer (CA ↔ SDK ↔ TS conformance) toolchain-аар өөрчлөгдөхгүйн тулд энд бэхэлнэ.
func nameString(n pkix.Name) string {
	var rdns pkix.RDNSequence
	if n.ExtraNames == nil {
		for _, atv := range n.Names {
			t := atv.Type
			if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
				switch t[3] {
				case 3, 5, 6, 7, 8, 9, 10, 11, 17:
					continue
				}
			}
			rdns = append(rdns, []pkix.AttributeTypeAndValue{atv})
		}
	}
	rdns = append(rdns, n.ToRDNSequence()...)
	s := ""
	for i := range rdns {
		rdn := rdns[len(rdns)-1-i]
		if i > 0 {
			s += ","
		}
		for j, tv := range rdn {
			if j > 0 {
				s += "+"
			}
			oid := tv.Type.String()
			typeName, ok := attributeTypeNames[oid]
			if !ok {
				if der, err := asn1.Marshal(tv.Value); err == nil {
					s += oid + "=#" + hex.EncodeToString(der)
					continue
				}
				typeName = oid
			}
			v := fmt.Sprint(tv.Value)
			esc := make([]rune, 0, len(v))
			for k, c := range v {
				e := false
				switch c {
				case ',', '+', '"', '\\', '<', '>', ';':
					e = true
				case ' ':
					e = k == 0 || k == len(v)-1
				case '#':
					e = k == 0
				}
				if e {
					esc = append(esc, '\\')
				}
				esc = append(esc, c)
			}
			s += typeName + "=" + string(esc)
		}
	}
	return s
}

var attributeTypeNames = map[string]string{
	"2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.3": "CN", "2.5.4.5": "SERIALNUMBER",
	"2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "STREET", "2.5.4.17": "POSTALCODE",
}
