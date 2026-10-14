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
	routeSignNotificationEtsi     = rpRoute{"POST", "/signature/notification/etsi/{semanticsIdentifier}"}
	routeSignNotificationDocument = rpRoute{"POST", "/signature/notification/document/{documentNumber}"}
	routePDFPrepare               = rpRoute{"POST", "/pdf/sign/prepare"}
	routePDFDocument              = rpRoute{"GET", "/pdf/sign/{sessionID}/document"}
	routeOrgRepresentations       = rpRoute{"GET", "/organization/representations/etsi/{personEtsi}"}
	routeSession                  = rpRoute{"GET", "/session/{sessionId}"}
)

// rpRoutes — SDK-ийн хамардаг бүх RP-API зам (гэрээний тестэд).
var rpRoutes = []rpRoute{
	routeAuthNotificationEtsi, routeAuthNotificationDocument, routeAuthDeviceLinkAnonymous, routeAuthDeviceLinkEtsi,
	routeSignNotificationEtsi, routeSignNotificationDocument,
	routePDFPrepare, routePDFDocument,
	routeOrgRepresentations,
	routeSession,
}

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
