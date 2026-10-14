- **OIDC: хатууруулалт.** (1) Танихгүй `kid`-ээр JWKS-ийг хүчээр дахин татах нь 30 сек тутамд нэгээс илүүгүй
  (`minRefetch`) — хуурамч kid-тэй token-оор `login.` руу ачаалал үүсгэхгүй. (2) `UseMTLSEndpointAliases: true` +
  `HTTPClient == nil` → `NewClient` алдаа (cert-гүй mTLS хүсэлт ойлгомжгүй 401 өгдөг байв). (3) `HandleCallback` —
  `CallbackChecks.CodeVerifier` / `Nonce` хоосон бол token солихоос өмнө `ErrInvalidCallback` (code дэмий зарцуулахгүй).
  Хаана: `oidc/oidc.go`, `oidc/oidc_test.go`.
- Шалгасан: `TestVerifyIDToken_KeyRotation` (minRefetch дотор refetch алга, хуурамч kid ×5 → JWKS татахгүй),
  `TestNewClient_Config`, `TestHandleCallback_Errors`. Засваргүйгээр 3 тест FAIL. `gofmt`, `go vet ./...`,
  `go test -race ./...`.
