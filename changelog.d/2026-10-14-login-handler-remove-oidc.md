- **BREAKING (v0.2.0): `oidc` багц хасагдсан; «eID-ээр нэвтрэх» = `eidlogin.Handler` (net/http) RP-API дээр.** eID-ийн
  OIDC provider (`login.eidmongolia.mn`) хасагдсан (2026-10-14 шийдвэр) тул `oidc/` (client, contract тест) ба README
  §2 OIDC устсан — openid-configuration прод дээр 404 болж `contract` job улаан байсан. Оронд нь Smart-ID RP-үүдийн
  хэв маяг: `eidlogin.New(Config{Client, OnSuccess, CallbackURL, Store?, RateLimit?, ClientIP?, …})`, `/auth/eid/`
  дор mount — `start` (POST qr | push; GET `?mode=web2app` → 302 eID апп, буцах хөтчийн `retScheme`/`retPkg` hint
  UA-аас), `status` (PENDING + секунд тутмын QR / WAIT_CALLBACK / OK / FAILED / EXPIRED), `callback` (Web2App +
  `userChallengeVerifier`). Төлөв серверт (`Store`, анхдагч `NewMemoryStore`), хөтчид HttpOnly cookie
  (`<sessionId>.<binding>`); callback зөвхөн эхлүүлсэн хөтчид (login CSRF); JSON-only POST + `Sec-Fetch-Site`; push-д
  анхдагч 3/мин нэг дугаарт; иргэн (`Identity`) зөвхөн `ValidateAuth`-ийн дараа `OnSuccess`-д. Хариуны хэлбэр TS SDK
  0.14.0-ийн `createEidLogin`-тэй ижил (хөтчийн товч `<eid-login-button>`). `Client.RPName()` нэмэгдсэн.
- Хаана: `eidlogin/eidlogin.go`, `eidlogin/eidlogin_test.go`, `client.go`, `doc.go`, `README.md` §2, `.github/workflows/contract.yml`.
- Шалгасан: `eidlogin` тест — fake RP-API (httptest) БОДИТ ACSP_V2 RSA-PSS гарын үсэг буцааж, `Validator` жинхэнээр
  шалгана: QR / push / Web2App, cookie binding, cookie-гүй callback татгалзах, буруу verifier, хуурамч гарын үсэг,
  flowType зөрөх (relay), CSRF, rate limit, нэг удаагийн OnSuccess. `gofmt`, `go vet ./...`, `go test -race ./...`,
  `GOOS=linux GOARCH=amd64 go build ./...`, `go test -tags contract -run Contract ./...` (live) ногоон.
