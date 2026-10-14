// Package eid — eID Mongolia relying-party SDK: иргэнийг утсаар нь нэвтрүүлэх (PIN1) ба хууль ёсны цахим гарын үсэг
// зуруулах (PIN2) RP-API v3 client (Smart-ID нийцтэй), device link v3 (QR / Web2App / App2App), хариуны
// криптограф баталгаажуулалт (гэрчилгээний гинж + ACSP_V2 / digest гарын үсэг), PAdES PDF гарын үсэг.
// «eID-ээр нэвтрэх» товчны backend (net/http) нь eidlogin дэд багцад.
//
// Зөвхөн backend-д: бүх дуудлага API secret (rp_sk_…)-ээр баталгаажна; secret, sessionSecret-ийг браузер/апп руу
// хэзээ ч гаргахгүй.
//
//	c, err := eid.NewClient(eid.Config{
//		Credentials: eid.Credentials{RPUUID: uuid, RPName: "Интернэт банк", APISecret: secret},
//		Trust: eid.TrustConfig{TrustAnchorsPEM: []string{eid.NationalRootCAPEM}, IntermediatesPEM: intermediates},
//	})
//	s, err := c.Auth.NotificationByEtsi(ctx, "PNOMN-12345678",
//		[]eid.Interaction{{Type: "displayTextAndPIN", DisplayText60: "Банкинд нэвтрэх"}}, nil)
//	show(s.VC) // ПИН биш — зөвхөн харуулна
//	r, err := c.Session.WaitForResult(ctx, s.SessionID, nil)
//	who, err := c.Validator.ValidateAuth(r, s.ACSP, eid.ValidateAuthOptions{ExpectedFlowType: eid.FlowNotification})
//
// Баримт: https://developer.eidmongolia.mn/
package eid
