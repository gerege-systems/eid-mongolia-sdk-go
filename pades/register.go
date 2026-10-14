package pades

import (
	"crypto/x509"
	"errors"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// RegistrationOptions — CA-ийн бүртгэлийн (POST /pdf/signatures) Completed-ээс гадуурх утгууд.
type RegistrationOptions struct {
	Medium     string // eid.PDFMediumPhone | eid.PDFMediumToken
	SessionID  string // утсанд заавал: DTBS-ийг зурсан RAW_DIGEST_SIGNATURE session
	OnBehalfOf string // NTRMN-… (PrepareOptions.ClaimedRole өгсөн бол заавал)
}

// Registration — Completed-ээс eid.PDFSignatureRegistration (CA dto-тэй ижил бие) бөглөнө; дараа нь
// eid.Client.PDF.RegisterSignature. SignerEtsi = гэрчилгээний SERIALNUMBER (CA CMS-тэй тулгана). Өмнөх гарын үсэг бүрийг
// PriorCMSSHA256-аар заагаад PriorSignatures-ийг (CMS + revision хос) бөглөнө: өмнөх мөр нь CA-ийн угсарсан (горим A,
// /pdf/sign/prepare) бол RegisterSignature 409 PRIOR_MISMATCH-ийн дараа revision-оор өөрөө тааруулна — дуудагч ангилах
// шаардлагагүй. Гараар ангилах бол PriorRevisionSHA256-г тавь (тэгвэл SDK оролдохгүй).
func Registration(c *Completed, o RegistrationOptions) (eid.PDFSignatureRegistration, error) {
	if c == nil {
		return eid.PDFSignatureRegistration{}, errors.New("pades: Completed nil")
	}
	if c.RevIndex == 1 && !c.HasPage {
		return eid.PDFSignatureRegistration{}, newErr(CodeRequestInvalid,
			"CA-ийн бүртгэлд эхний гарын үсэг баталгаажуулалтын хуудастай байна (PrepareOptions.VerifyPage)", nil)
	}
	if c.FileName == "" {
		return eid.PDFSignatureRegistration{}, newErr(CodeRequestInvalid, "fileName хоосон (PrepareOptions.FileName)", nil)
	}
	r := eid.PDFSignatureRegistration{
		DocID: c.DocID, RevIndex: c.RevIndex, Medium: o.Medium, SessionID: o.SessionID, CMS: c.CMS, FileName: c.FileName,
		InSHA256: c.InSHA256, SigRevSHA256: c.SigRevSHA256, OutSHA256: c.OutSHA256, OnBehalfOf: o.OnBehalfOf,
	}
	if c.RevIndex == 1 {
		r.PageSHA256 = c.PageSHA256
	}
	if len(c.PriorCMSSHA256) > 0 {
		r.PriorCMSSHA256 = append([]string(nil), c.PriorCMSSHA256...)
		if len(c.PriorRevisionSHA256) == len(c.PriorCMSSHA256) {
			for i, h := range c.PriorCMSSHA256 {
				r.PriorSignatures = append(r.PriorSignatures, eid.PDFPriorSignature{CMSSHA256: h, RevisionSHA256: c.PriorRevisionSHA256[i]})
			}
		}
	}
	if cert, err := x509.ParseCertificate(c.SignerCert); err == nil {
		r.SignerEtsi = cert.Subject.SerialNumber
	}
	return r, nil
}
