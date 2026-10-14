package pades

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"time"

	"crypto"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// CompleteOptions — Complete-ийн тохиргоо.
type CompleteOptions struct {
	// HTTPClient — TSA/OCSP/CRL-ийн HTTP (sandbox, proxy, тест). nil бол timeout 10 с, redirect үгүй.
	HTTPClient *http.Client `json:"-"`
	// TSAURL — RFC 3161 TSA; хоосон бол DefaultTSAURL.
	TSAURL string `json:"tsaUrl,omitempty"`
	// Now — цаг (тест); nil бол time.Now.
	Now func() time.Time `json:"-"`
	// Roots — итгэлийн тулгуур DER (TSA гинж, self-validation); хоосон бол Mongolian National Root CA.
	Roots [][]byte `json:"roots,omitempty"`
}

// Completed — гарын үсэгтэй PDF + CA-ийн бүртгэлд (POST /pdf/signatures, docs/PADES_CLIENT_SIDE.md §4.3) хэрэгтэй
// утгууд (hash нь жижиг hex).
type Completed struct {
	PDF            []byte
	DocID          string
	CMS            []byte // /Contents-д суусан CMS DER
	OutSHA256      string // гаралт (DSS revision-тэй)
	InSHA256       string // Prepare-ийн оролт
	HasPage        bool   // энэ гарын үсгийн өмнө баталгаажуулалтын хуудас нэмэгдсэн
	PageSHA256     string // хуудас нэмсний дараах (R_sig-ээс өмнөх) баримт; HasPage үед
	SignerCert     []byte
	RevIndex       int      // энэ гарын үсгийн дугаар (1…16)
	SigRevSHA256   string   // гарын үсгийн revision (DSS-ээс өмнөх) — doc[:ByteRange end]
	PriorCMSSHA256 []string // өмнөх гарын үсгүүдийн CMS DER-ийн sha256 (баримтын дарааллаар)
}

// Complete — иргэний гарын үсгийг DTBS дээр шалгаад TSA → CMS → embed → OCSP/CRL (genTime-ийн дараа) → DSS →
// self-validation (CA-ийн нийтийн шалгагч) → PAdES-BASELINE-LT баримт. signature: RSA PKCS#1 v1.5, ECDSA r‖s (P-256 64
// байт, P-384 96 байт) эсвэл DER — гэрчилгээний түлхүүрээр автоматаар.
func Complete(ctx context.Context, state []byte, signature []byte, o CompleteOptions) (*Completed, error) {
	st, err := decodeState(state)
	if err != nil {
		return nil, newErr(CodeStateInvalid, "state задарсангүй", err)
	}
	cert, err := x509.ParseCertificate(st.SignerCert)
	if err != nil {
		return nil, newErr(CodeStateInvalid, "state-ийн signerCert", err)
	}
	chain, err := parseDERs(st.Chain)
	if err != nil {
		return nil, newErr(CodeStateInvalid, "state-ийн chain", err)
	}
	roots, err := parseRoots(o.Roots)
	if err != nil {
		return nil, newErr(CodeRequestInvalid, "roots", err)
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	tsaURL := o.TSAURL
	if tsaURL == "" {
		tsaURL = DefaultTSAURL
	}
	dtbs := core.DTBS(st.SignedAttrs)
	sig, ok := citizenSignature(cert.PublicKey, dtbs, signature)
	if !ok {
		return nil, newErr(CodeSignatureInvalid, "гарын үсэг DTBS-тэй таарсангүй", nil)
	}
	f := newFetcher(o.HTTPClient)
	tst, ts, err := timestampToken(ctx, f, tsaURL, sig, roots, chain, now())
	if err != nil {
		return nil, newErr(CodeTSAUnavailable, "TSA timestamp авч чадсангүй", err)
	}
	cms, err := core.AssembleCMS(st.SignedAttrs, cert, chain, sig, tst)
	if err != nil {
		return nil, newErr(CodeSelfValidationFailed, "CMS угсарч чадсангүй", err)
	}
	signed, err := core.EmbedCMS(st.PDF, st.ByteRange, cms)
	if errors.Is(err, core.ErrPlaceholderOverflow) {
		return nil, newErr(CodePlaceholderOverflow, "CMS placeholder-т багтсангүй", err)
	}
	if err != nil {
		return nil, newErr(CodeStateInvalid, "CMS-ийг placeholder-т бичиж чадсангүй", err)
	}
	citizenChain := append([]*x509.Certificate{cert}, chain...)
	dss, err := collectLTVWithWait(ctx, f, now, ts.Time, roots, citizenChain, ts.Certificates)
	if err != nil {
		return nil, newErr(CodeLTVUnavailable, "OCSP/CRL бүрэн авч чадсангүй", err)
	}
	if dss.Contents, err = core.SignatureContents(signed, st.ByteRange); err != nil {
		return nil, newErr(CodeSelfValidationFailed, "/Contents уншиж чадсангүй", err)
	}
	out, err := core.AppendDSS(signed, dss)
	if err != nil {
		return nil, newErr(CodeSelfValidationFailed, "DSS revision бичиж чадсангүй", err)
	}
	if len(out) > MaxOutputBytes {
		return nil, newErr(CodePDFTooLarge, "гаралт 10 MiB-аас их", nil)
	}
	// Self-validation — CA-ийн padesSelfCheck: бүх гарын үсэг valid + B-LT, тоо = revIndex, шинэ гарын үсэг байна.
	raws, err := validate.Extract(out)
	if err != nil {
		return nil, newErr(CodeSelfValidationFailed, "гаралтыг задалж чадсангүй", err)
	}
	v := newValidator(roots, append(append([]*x509.Certificate{}, chain...), ts.Certificates...), chain[:1], now, raws)
	rep, err := v.ValidatePDF(ctx, out)
	if err != nil {
		return nil, newErr(CodeSelfValidationFailed, "self-validation ажилласангүй", err)
	}
	sigRev := sha256.Sum256(signed)
	sigRevHex := hex.EncodeToString(sigRev[:])
	if !selfCheck(rep, st.RevIndex, sigRevHex) {
		return nil, newErr(CodeSelfValidationFailed, "гаралт PAdES-BASELINE-LT-ээр батлагдсангүй", nil)
	}
	outSum := sha256.Sum256(out)
	res := &Completed{PDF: out, DocID: st.DocID, CMS: cms, OutSHA256: hex.EncodeToString(outSum[:]), InSHA256: st.InSHA256,
		HasPage: st.HasPage, PageSHA256: st.PageSHA256, SignerCert: cert.Raw, RevIndex: st.RevIndex, SigRevSHA256: sigRevHex}
	for _, r := range raws[:len(raws)-1] {
		res.PriorCMSSHA256 = append(res.PriorCMSSHA256, r.CMSSHA256)
	}
	return res, nil
}

// selfCheck — CA padesSelfCheck.
func selfCheck(rep *validate.PDFReport, revIndex int, sigRev string) bool {
	if rep == nil || rep.Indication != validate.Valid || len(rep.Signatures) != revIndex {
		return false
	}
	found := false
	for _, s := range rep.Signatures {
		if s.Indication != validate.Valid || s.LTV == nil || !s.LTV.Complete || s.SignatureLevel != "PAdES-BASELINE-LT" {
			return false
		}
		found = found || s.RevisionSHA256 == sigRev
	}
	return found
}

// citizenSignature — DTBS дээрх гарын үсгийг шалгаж CMS-д бичих хэлбэрээр (RSA — хэвээр, ECDSA — DER) буцаана.
// RSA нь зөвхөн PKCS#1 v1.5 (CMS-ийн sha256WithRSAEncryption-тэй таарна).
func citizenSignature(pub crypto.PublicKey, dtbs, sig []byte) ([]byte, bool) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return sig, rsa.VerifyPKCS1v15(k, crypto.SHA256, dtbs, sig) == nil
	case *ecdsa.PublicKey:
		n := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) == 2*n { // r‖s (PKCS#11 CKM_ECDSA, утас)
			r, s := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
			if der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s}); err == nil && ecdsa.VerifyASN1(k, dtbs, der) {
				return der, true
			}
		}
		return sig, ecdsa.VerifyASN1(k, dtbs, sig)
	}
	return nil, false
}
