- **v0.3.1 — `eidlogin`: өөрийн хязгаар өгөхөд анхдагч push хязгаар алдагддаг байсан (TS 0.15.1-тэй зэрэгцүүлсэн).**
  - `Config.RateLimit` өгөхөд анхдагч (push — нэг дугаарт 3/мин, MFA fatigue) чимээгүй унтардаг байв. Одоо
    `Config.RateLimits map[string]RateRule` (`"start"` | `"push"`) `DefaultRateLimit()`-тэй төрөл тус бүрээр нэгтгэгдэнэ
    (`RateRule{Max, Window}` санах ойн цонх | `{Func}` | `{}` хязгааргүй); `Config.RateLimit` функц анхдагч ДЭЭР
    нэмэгдэнэ. `DefaultRateLimit()` export (шинэ map). Буруу түлхүүр / Window ≤ 0 → `New` алдаа.
  - README: хязгаарлалтын хэсэг, товчны CDN 0.15.1, dark токен (`--eid-<нэр>-dark`) заалт, install v0.3.1.
- Хаана: `eidlogin/eidlogin.go`, `eidlogin/eidlogin_test.go`, `README.md` §2.
- Шалгасан: `TestRateLimitsMergeKeepsDefaultPush` (зөвхөн start өгөхөд push 3/мин идэвхтэй), `TestRateLimitFuncAddsToDefault`,
  `TestRateLimitsOverridePush` (window/off/func, start window), `TestDefaultRateLimitAndValidation`; `gofmt`, `go vet`,
  `go test ./...` (+ `-race` eidlogin), `GOOS=linux GOARCH=amd64 go build`.
