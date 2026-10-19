package validate

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Цуцлалтын нотолгооны (OCSP/CRL) шинэлэг байдал ба тохирлын нэг дүрэм — DSS (offline), онлайн OCSP/CRL, LTV
// хамралт, Complete-ийн DSS цуглуулалт бүгд үүгээр шийднэ (native SDK-ууд ижлээр давтана; golden validate/v4).
const (
	// RevocationMaxAge — nextUpdate-гүй (эсвэл шалгах цагийг хамраагүй) хариуны thisUpdate нь шалгах цагаас
	// хамгийн ихдээ ийм хугацаагаар өмнө байж болно (§8.3; LTV-д шалгах цаг = цагийн тэмдгийн цаг).
	RevocationMaxAge = 24 * time.Hour
	// RevocationClockSkew — responder ба шалгагчийн цагийн зөрүүний хүлцэл (thisUpdate «ирээдүйд», nextUpdate
	// саяхан өнгөрсөн).
	RevocationClockSkew = 5 * time.Minute
)

// FreshAt — thisUpdate/nextUpdate-тэй хариу (OCSP SingleResponse эсвэл CRL) at агшны «good» нотолгоо болох эсэх:
//   - thisUpdate тэг биш, now+skew-ээс хожуу биш (ирээдүйд гаргасан хариу биш);
//   - nextUpdate (байвал) at−skew-ээс өмнө биш (at-д хүчингүй болсон хариу биш);
//   - thisUpdate ≥ at − RevocationMaxAge (хангалттай шинэ), эсвэл [thisUpdate, nextUpdate] нь at-ийг хамарна.
//
// at — шалгах цаг (итгэмжлэгдсэн цагийн тэмдэгтэй бол түүний цаг, эс бөгөөс now); now — шалгагчийн «одоо»
// (ValidateOptions.Time эсвэл time.Now). «Revoked» нотолгоонд хамаарахгүй — цуцлалт буцахгүй тул хуучин ч хүчинтэй.
func FreshAt(thisUpdate, nextUpdate, at, now time.Time) bool {
	if thisUpdate.IsZero() || thisUpdate.After(now.Add(RevocationClockSkew)) {
		return false
	}
	if !nextUpdate.IsZero() && nextUpdate.Before(at.Add(-RevocationClockSkew)) {
		return false
	}
	if !thisUpdate.Before(at.Add(-RevocationMaxAge)) {
		return true
	}
	return !nextUpdate.IsZero() && !thisUpdate.After(at)
}

// CRLFor — crl нь cert-ийн олгогчийнх: crl.RawIssuer = cert.RawIssuer = issuer.RawSubject, AKI (хоёуланд байвал) =
// issuer-ийн SKI, гарын үсэг issuer-ийн түлхүүрээр.
func CRLFor(crl *x509.RevocationList, cert, issuer *x509.Certificate) bool {
	if !bytes.Equal(crl.RawIssuer, cert.RawIssuer) || !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return false
	}
	if len(crl.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 && !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return false
	}
	return crl.CheckSignatureFrom(issuer) == nil
}

// CRLListed — cert-ийн serial crl-д байвал цуцалсан цагийг буцаана.
func CRLListed(crl *x509.RevocationList, cert *x509.Certificate) (time.Time, bool) {
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return e.RevocationTime, true
		}
	}
	return time.Time{}, false
}

// OCSPCertIDMatches — OCSP хариуны (DER) cert.SerialNumber-тэй SingleResponse БҮР нь issuer-ийн CertID-тэй
// (issuerNameHash = H(issuer subject), issuerKeyHash = H(issuer subjectPublicKey); SHA-1/256/384/512) бөгөөд дор
// хаяж нэг нь байна. x/crypto/ocsp.ParseResponseForCert нь зөвхөн serial-аар сонгодог тул өөр олгогчийн ижил
// serial-ийн хариу (ижил responder зурсан ч) энэ гэрчилгээнд тооцогдохгүй.
func OCSPCertIDMatches(der []byte, cert, issuer *x509.Certificate) bool {
	keyBits, ok := spkiKeyBits(issuer.RawSubjectPublicKeyInfo)
	if !ok {
		return false
	}
	var resp, rb, basic, tbs, singles cryptobyte.String
	var status int
	var oid asn1.ObjectIdentifier
	var rid cryptobyte.String
	var ridTag cbasn1.Tag
	in := cryptobyte.String(der)
	if !in.ReadASN1(&resp, cbasn1.SEQUENCE) ||
		!resp.ReadASN1Enum(&status) || status != 0 ||
		!resp.ReadASN1(&rb, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!rb.ReadASN1(&rb, cbasn1.SEQUENCE) ||
		!rb.ReadASN1ObjectIdentifier(&oid) ||
		!rb.ReadASN1(&basic, cbasn1.OCTET_STRING) ||
		!basic.ReadASN1(&basic, cbasn1.SEQUENCE) ||
		!basic.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!tbs.SkipOptionalASN1(cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.ReadAnyASN1Element(&rid, &ridTag) || // responderID
		!tbs.SkipASN1(cbasn1.GeneralizedTime) || // producedAt
		!tbs.ReadASN1(&singles, cbasn1.SEQUENCE) {
		return false
	}
	found := false
	for !singles.Empty() {
		var single, certID, alg cryptobyte.String
		var hashOID asn1.ObjectIdentifier
		var nameHash, keyHash []byte
		serial := new(big.Int)
		if !singles.ReadASN1(&single, cbasn1.SEQUENCE) ||
			!single.ReadASN1(&certID, cbasn1.SEQUENCE) ||
			!certID.ReadASN1(&alg, cbasn1.SEQUENCE) ||
			!alg.ReadASN1ObjectIdentifier(&hashOID) ||
			!certID.ReadASN1Bytes(&nameHash, cbasn1.OCTET_STRING) ||
			!certID.ReadASN1Bytes(&keyHash, cbasn1.OCTET_STRING) ||
			!certID.ReadASN1Integer(serial) {
			return false
		}
		if serial.Cmp(cert.SerialNumber) != 0 {
			continue
		}
		h, ok := ocspHashes[hashOID.String()]
		if !ok || !h.Available() {
			return false
		}
		if !bytes.Equal(nameHash, hashOf(h, issuer.RawSubject)) || !bytes.Equal(keyHash, hashOf(h, keyBits)) {
			return false
		}
		found = true
	}
	return found
}

var ocspHashes = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

func hashOf(h crypto.Hash, b []byte) []byte {
	w := h.New()
	w.Write(b)
	return w.Sum(nil)
}

// spkiKeyBits — SubjectPublicKeyInfo-ийн subjectPublicKey BIT STRING-ийн байт (RFC 6960 issuerKeyHash-ийн оролт).
func spkiKeyBits(spki []byte) ([]byte, bool) {
	var seq cryptobyte.String
	var bits asn1.BitString
	in := cryptobyte.String(spki)
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.SkipASN1(cbasn1.SEQUENCE) || !seq.ReadASN1BitString(&bits) {
		return nil, false
	}
	return bits.Bytes, true
}
