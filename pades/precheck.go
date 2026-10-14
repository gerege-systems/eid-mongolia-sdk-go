package pades

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pkcs7"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// precheck — PRECHECKS.md-ийн «хөнгөн» шалгуур (validator-гүй; native SDK-ууд яг ижлээр давтана). Буцаах: шинэ баримт
// эсэх (гарын үсгийн объект алга), энэ гарын үсгийн revIndex. issuers — eID олгогч CA (04/05 + signer-ийн олгогч).
func precheck(doc []byte, issuers []*x509.Certificate) (newDoc bool, revIndex int, err error) {
	if encrypted(doc) {
		return false, 0, newErr(CodePDFEncrypted, "шифрлэгдсэн PDF дэмжигдэхгүй", nil)
	}
	sigs, locked, hasDSS, err := scanSignatures(doc)
	if err != nil {
		return false, 0, newErr(CodePDFInvalid, "PDF биш эсвэл эвдэрсэн", err)
	}
	if len(sigs) == 0 {
		return true, 1, nil
	}
	if len(sigs) >= MaxSignatures {
		return false, 0, newErr(CodePDFTooManySignatures, "баримтад хэт олон гарын үсэг байна", nil)
	}
	leaves := make([]*x509.Certificate, len(sigs))
	stamped := make([]bool, len(sigs))
	for i, s := range sigs {
		leaf, ts, err := checkPriorSignature(doc, s)
		if err != nil {
			return false, 0, newErr(CodePDFPriorSignatureInvalid, "өмнөх гарын үсэг хүчингүй", err)
		}
		leaves[i], stamped[i] = leaf, ts
	}
	if locked {
		return false, 0, newErr(CodePDFLocked, "баримт certification (DocMDP P=1) гарын үсгээр түгжигдсэн", nil)
	}
	for i, s := range sigs {
		if s.subFilter != "ETSI.CAdES.detached" || !issuedByAny(leaves[i], issuers) || !stamped[i] || !hasDSS {
			return false, 0, newErr(CodePDFForeignSignature, "баримтад eID-ийн биш гарын үсэг байна", nil)
		}
	}
	return false, len(sigs) + 1, nil
}

type sigDict struct {
	obj       uint32
	byteRange []int64
	subFilter string
}

// scanSignatures — xref-ийн (сүүлийн revision) объект бүрээс /ByteRange ба /Contents хоёулаа бүхий толь (объектын
// дугаараар эрэмбэлсэн) ба DocMDP P=1 түгжээ (Catalog /Perms /DocMDP эсвэл аль нэг Sig-ийн /Reference).
func scanSignatures(doc []byte) (sigs []sigDict, locked, hasDSS bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			sigs, locked, hasDSS, err = nil, false, false, fmt.Errorf("PDF задлах: %v", r)
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		return nil, false, false, err
	}
	if r.Trailer().Key("Root").Kind() != pdf.Dict {
		return nil, false, false, errors.New("Catalog алга")
	}
	hasDSS = r.Trailer().Key("Root").Key("DSS").Kind() == pdf.Dict
	if docMDPP1(r.Trailer().Key("Root").Key("Perms").Key("DocMDP")) {
		locked = true
	}
	for _, x := range r.Xref() {
		v := r.Resolve(x.Ptr(), x.Ptr())
		if v.Kind() != pdf.Dict || v.Key("ByteRange").IsNull() || v.Key("Contents").IsNull() {
			continue
		}
		ptr := x.Ptr()
		s := sigDict{obj: ptr.GetID(), subFilter: v.Key("SubFilter").Name()}
		br := v.Key("ByteRange")
		for i := range br.Len() {
			e := br.Index(i)
			if e.Kind() != pdf.Integer {
				s.byteRange = nil
				break
			}
			s.byteRange = append(s.byteRange, e.Int64())
		}
		if docMDPP1(v) {
			locked = true
		}
		sigs = append(sigs, s)
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].obj < sigs[j].obj })
	return sigs, locked, hasDSS, nil
}

// docMDPP1 — Sig толийн /Reference массивын аль нэг мөр /TransformMethod /DocMDP, /TransformParams /P 1.
func docMDPP1(sig pdf.Value) bool {
	ref := sig.Key("Reference")
	for i := range ref.Len() {
		e := ref.Index(i)
		m := e.Key("TransformMethod")
		if (m.IsNull() || m.Name() == "DocMDP") && e.Key("TransformParams").Key("P").Kind() == pdf.Integer &&
			e.Key("TransformParams").Key("P").Int64() == 1 {
			return true
		}
	}
	return false
}

// checkPriorSignature — ByteRange [0 a b c]: a > 0, doc[a] = '<', doc[b-1] = '>', b+c ≤ len; /Contents-ийн hex-ийн эхний
// ASN.1 элемент = CMS SignedData, signer ганц, гарын үсэг (messageDigest + signedAttrs) ByteRange-ийн байт дээр
// криптограф хүчинтэй. Гинж/цуцлалт шалгахгүй (validator-ийн ажил).
func checkPriorSignature(doc []byte, s sigDict) (leaf *x509.Certificate, stamped bool, err error) {
	br := s.byteRange
	if len(br) != 4 || br[0] != 0 || br[1] <= 0 || br[2] <= br[1]+1 || br[3] < 0 || br[2]+br[3] > int64(len(doc)) {
		return nil, false, errors.New("ByteRange буруу")
	}
	a, b := br[1], br[2]
	if doc[a] != '<' || doc[b-1] != '>' {
		return nil, false, errors.New("ByteRange нь /Contents-ийг заахгүй")
	}
	// Гарын үсгийн revision-ий төгсгөл: doc[:b+c]-ийн төгсгөлийн CR/LF-ийг хассаны дараа "%%EOF".
	if !bytes.HasSuffix(bytes.TrimRight(doc[:b+br[3]], "\r\n"), []byte("%%EOF")) {
		return nil, false, errors.New("ByteRange нь revision-ий төгсгөл (%%EOF) хүртэл биш")
	}
	raw := make([]byte, (b-a-2)/2)
	if (b-a-2)%2 != 0 {
		return nil, false, errors.New("/Contents hex сондгой")
	}
	if _, err := hex.Decode(raw, doc[a+1:b-1]); err != nil {
		return nil, false, fmt.Errorf("/Contents hex: %w", err)
	}
	in := cryptobyte.String(raw)
	var der cryptobyte.String
	if !in.ReadASN1Element(&der, cbasn1.SEQUENCE) {
		return nil, false, errors.New("CMS DER биш")
	}
	p7, err := pkcs7.Parse(der)
	if err != nil || len(p7.Signers) != 1 {
		return nil, false, errors.New("CMS задрахгүй / signer ганц биш")
	}
	if leaf = p7.GetOnlySigner(); leaf == nil {
		return nil, false, errors.New("signer cert алга")
	}
	signed := make([]byte, 0, br[1]+br[3])
	signed = append(append(signed, doc[:a]...), doc[b:b+br[3]]...)
	p7.Content = signed
	if err := p7.Verify(); err != nil {
		return nil, false, fmt.Errorf("гарын үсэг: %w", err)
	}
	for _, at := range p7.Signers[0].UnauthenticatedAttributes {
		stamped = stamped || at.Type.Equal(oidSignatureTimeStampToken)
	}
	return leaf, stamped, nil
}

var oidSignatureTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// issuedByAny — leaf-ийн олгогч нь issuers-ийн аль нэг (subject DN тэнцүү + гарын үсэг шалгагдсан).
func issuedByAny(leaf *x509.Certificate, issuers []*x509.Certificate) bool {
	for _, is := range issuers {
		if bytes.Equal(leaf.RawIssuer, is.RawSubject) && leaf.CheckSignatureFrom(is) == nil {
			return true
		}
	}
	return false
}
