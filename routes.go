package eid

import (
	"net/url"
	"strings"
)

// rpRoute — SDK-ийн дууддаг RP-API зам (method + {param}-тай template). Бүх зам ЗӨВХӨН энд тодорхойлогдоно:
// гэрээний тест (contract_test.go, `go test -tags contract`) энэ жагсаалтыг live /.well-known/eid-тэй тулгадаг.
type rpRoute struct {
	method string
	path   string
}

var (
	routeAuthNotificationEtsi     = rpRoute{"POST", "/authentication/notification/etsi/{semanticsIdentifier}"}
	routeAuthNotificationDocument = rpRoute{"POST", "/authentication/notification/document/{documentNumber}"}
	routeAuthDeviceLinkAnonymous  = rpRoute{"POST", "/authentication/device-link/anonymous"}
	routeAuthDeviceLinkEtsi       = rpRoute{"POST", "/authentication/device-link/etsi/{semanticsIdentifier}"}
	routeAuthQR                   = rpRoute{"POST", "/authentication/qr"}
	routeSignNotificationEtsi     = rpRoute{"POST", "/signature/notification/etsi/{semanticsIdentifier}"}
	routeSignNotificationDocument = rpRoute{"POST", "/signature/notification/document/{documentNumber}"}
	routeSignNotificationLinked   = rpRoute{"POST", "/signature/notification/linked/{documentNumber}"}
	routeSignDeviceLinkEtsi       = rpRoute{"POST", "/signature/device-link/etsi/{semanticsIdentifier}"}
	routeSignDeviceLinkDocument   = rpRoute{"POST", "/signature/device-link/document/{documentNumber}"}
	routeCertChoiceDeviceLink     = rpRoute{"POST", "/signature/certificate-choice/device-link/anonymous"}
	routeCertChoiceEtsi           = rpRoute{"POST", "/signature/certificate-choice/notification/etsi/{semanticsIdentifier}"}
	routePDFSignatures            = rpRoute{"POST", "/pdf/signatures"}
	routeOrgRepresentations       = rpRoute{"GET", "/organization/representations/etsi/{personEtsi}"}
	routeSession                  = rpRoute{"GET", "/session/{sessionId}"}
	routePersonCertificates       = rpRoute{"GET", "/certificates/etsi/{personEtsi}"}
	routePersonDevices            = rpRoute{"GET", "/devices/etsi/{personEtsi}"}
	routePersonActivity           = rpRoute{"GET", "/rp/activity/etsi/{personEtsi}"}
	routePersonSummary            = rpRoute{"GET", "/person/summary/etsi/{personEtsi}"}
	routePersonChildren           = rpRoute{"GET", "/person/children/etsi/{personEtsi}"}
	routeTokenCertificate         = rpRoute{"POST", "/token/certificate"}
	routeTokenCertificateResult   = rpRoute{"GET", "/token/certificate/{sessionID}"}
	routeTokenAuthChallenge       = rpRoute{"POST", "/token/auth/challenge"}
	routeTokenAuthVerify          = rpRoute{"POST", "/token/auth/verify"}
	routeShare                    = rpRoute{"POST", "/share"}
)

// rpRoutes — SDK-ийн хамардаг бүх RP-API зам (гэрээний тестэд).
var rpRoutes = []rpRoute{
	routeAuthNotificationEtsi, routeAuthNotificationDocument, routeAuthDeviceLinkAnonymous, routeAuthDeviceLinkEtsi,
	routeAuthQR,
	routeSignNotificationEtsi, routeSignNotificationDocument, routeSignNotificationLinked,
	routeSignDeviceLinkEtsi, routeSignDeviceLinkDocument,
	routeCertChoiceDeviceLink, routeCertChoiceEtsi,
	routePDFSignatures,
	routeOrgRepresentations,
	routeSession,
	routePersonCertificates, routePersonDevices, routePersonActivity, routePersonSummary, routePersonChildren,
	routeTokenCertificate, routeTokenCertificateResult,
	routeTokenAuthChallenge, routeTokenAuthVerify,
	routeShare,
}

// rpRoutesUndiscovered — CA-ийн гэрээнд (код + docs) байгаа ч live /.well-known/eid-д хараахан жагсаагдаагүй замууд.
// Гэрээний тест эдгээрийг WARN болгоно (fail биш); discovery-д нэмэгдмэгц rpRoutes руу шилжүүлнэ. Одоогоор хоосон —
// /token/auth/* discovery-ийн endpoints.token.auth_challenge / auth_verify-д орсон тул rpRoutes-д.
var rpRoutesUndiscovered = []rpRoute{}

// expand — template-ийн {param}-уудыг дарааллаар нь url.PathEscape хийсэн args-аар орлуулна.
func (r rpRoute) expand(args ...string) string {
	var b strings.Builder
	rest := r.path
	for _, a := range args {
		i := strings.IndexByte(rest, '{')
		j := strings.IndexByte(rest, '}')
		if i < 0 || j < i {
			panic("eid: route " + r.path + ": параметр илүү")
		}
		b.WriteString(rest[:i])
		b.WriteString(url.PathEscape(a))
		rest = rest[j+1:]
	}
	if strings.IndexByte(rest, '{') >= 0 {
		panic("eid: route " + r.path + ": параметр дутуу")
	}
	b.WriteString(rest)
	return b.String()
}
