package pades_test

import (
	"context"
	"encoding/base64"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades"
)

// Example — README §7-той ижил урсгал (compile-оор шалгагдана): certificate-choice → (байгууллагын нэрийн өмнөөс бол)
// claimedRole → Prepare → DigestForSigner (sha256WithRSAEncryption) → Complete → RegisterSignature.
func Example() {
	ctx := context.Background()
	var c *eid.Client   // eid.NewClient(...)
	var pdfBytes []byte // RP-ийн өөрийн серверт байгаа PDF
	personEtsi, orgEtsi := "PNOMN-12345678", "NTRMN-6235972"
	run := func() error {
		cc, err := c.Sign.CertificateChoiceByEtsi(ctx, personEtsi, nil)
		if err != nil {
			return err
		}
		r, err := c.Session.WaitForResult(ctx, cc.SessionID, nil)
		if err != nil {
			return err
		}
		signer, err := c.Validator.ValidateCertificateChoice(r, cc.SessionID)
		if err != nil {
			return err
		}
		reps, err := c.Organization.GetRepresentations(ctx, personEtsi)
		if err != nil {
			return err
		}
		claimedRole := ""
		for _, rep := range reps.Representations {
			if rep.OrgEtsi == orgEtsi {
				claimedRole = rep.ClaimedRole
			}
		}
		p, err := pades.Prepare(pdfBytes, pades.PrepareOptions{
			SignerCert: signer.Certificate.Raw, VerifyPage: true, FileName: "Гэрээ №12.pdf",
			ClaimedRole: claimedRole, Reason: "Тест ХХК-ийг төлөөлж",
		})
		if err != nil {
			return err
		}
		// DigestForSigner / DeviceLinkForSigner-ийн анхдагч = sha256WithRSAEncryption (PKCS#1 v1.5) — CMS-д заавал.
		s, err := c.Sign.DigestForSigner(ctx, signer, base64.StdEncoding.EncodeToString(p.DTBS),
			[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "Баримтад гарын үсэг зурах: Гэрээ №12.pdf"}},
			&eid.SignOptions{OnBehalfOf: orgEtsi})
		if err != nil {
			return err
		}
		res, err := c.Session.WaitForResult(ctx, s.SessionID, nil)
		if err != nil {
			return err
		}
		if _, err := c.Validator.ValidateSign(res, s.Sign.Digest, s.Sign.HashAlgorithm, eid.ValidateSignOptions{
			ExpectedAlgorithm: s.Sign.SignatureAlgorithm, ExpectedCertificate: signer.Certificate,
			ExpectedFlowType: eid.FlowNotification}); err != nil {
			return err
		}
		sig, err := base64.StdEncoding.DecodeString(res.SignatureValueB64)
		if err != nil {
			return err
		}
		done, err := pades.Complete(ctx, p.State, sig, pades.CompleteOptions{})
		if pades.ErrorCode(err) == pades.CodeTSAUnavailable {
			return err // p.State хэвээр — дахин оролдоно
		}
		if err != nil {
			return err
		}
		reg, err := pades.Registration(done, pades.RegistrationOptions{Medium: eid.PDFMediumPhone, SessionID: s.SessionID,
			OnBehalfOf: orgEtsi})
		if err != nil {
			return err
		}
		if _, err := c.PDF.RegisterSignature(ctx, reg); err != nil {
			return err
		}
		_ = done.PDF // RP хадгална / хэрэглэгчид өгнө
		return nil
	}
	if c != nil {
		_ = run()
	}
}
