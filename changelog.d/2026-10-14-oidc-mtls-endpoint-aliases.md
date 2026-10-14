- **OIDC: `mtls_endpoint_aliases` (RFC 8705 §5)** — v0.1.6. `login.` хост mTLS хийдэггүй тул `require_mtls`-тэй RP
  code солиход `login.eidmongolia.mn/oauth2/token` дээр `401 invalid_client` авдаг байв. CA !347 discovery-д
  `mtls_endpoint_aliases.token_endpoint` (`https://rp.eidmongolia.mn/oauth2/token`, RP client cert шаардана) нэмсэн.
  `oidc.Discovery.MTLSEndpointAliases map[string]string`; `oidc.Config.UseMTLSEndpointAliases` (анхдагч false) — true +
  alias байвал token хүсэлт alias руу; alias алга бол `TokenEndpoint` руу буцна; alias https биш бол
  `ErrDiscoveryFailed`. Client cert нь `Config.HTTPClient`-ийн Transport-оор (RP-API-тай ижил). README: «mTLS-тэй RP».
  Хаана: `oidc/oidc.go`, `oidc/oidc_test.go`. TS SDK 0.13.0-тай ижил.
- Шалгасан: `TestMTLSEndpointAliases` — флагтай → alias, флаггүй → `token_endpoint`, alias алга → fallback, `http://`
  alias → `discovery_failed` (token хүсэлт явахгүй). `gofmt`, `go vet ./...`, `go test -race ./...`,
  `GOOS=linux GOARCH=amd64 go build ./...`.
