### Changed — `eidlogin`: хугацаа CA-ийн session-оос урт байхгүй; `Auth.SessionTTL` (discovery `sessionTtl`)

- **Юу:** `c.Auth.SessionTTL(ctx)` — discovery `/.well-known/eid`-ийн `sessionTtl` (`Auth`, `Sign`; хуучин CA-д 0).
  `eidlogin`: start-ийн `expiresIn`, cookie `Max-Age`, store-ийн хугацаа = QR/Web2App-д min(`Config.TTL`, CA-ийн
  `expiresAt` − одоо); push-д (бодит ба decoy ижил) min(`Config.TTL`, discovery `sessionTtl.auth`, 10 мин кэш). Хуучин
  CA-д бодит push-ийн `expiresAt`-аас ажигласан утгыг decoy авна. `Config.TTL`-ийн анхдагч (2 мин) хэвээр.
- **Яагаад:** RP `TTL`-ийг CA-ийнхаас урт тохируулбал иргэн CA дууссан session-ийг хүлээж үлддэг; decoy-д CA хариу
  байхгүй тул CA-ийн `expiresAt`-аар таслах нь бодит/decoy push-ийн хугацааг ялгаж (бүртгэлтэй эсэхийн oracle) болох байв.
- **Хаана:** `auth.go` (`SessionTTL`), `eidlogin/eidlogin.go` (`authTTL`, `observeAuthTTL`, `begin`/`save`/`startDecoy`),
  README (eidlogin §хугацаа, `ExpiresAt`), `portal_gaps_test.go` (`TestAuthSessionTTL`), `eidlogin/security_test.go`
  (`TestPushTTLFromDiscovery`, `TestPushTTLObservedWithoutDiscovery`, `TestQRTTLCappedByCAExpiresAt`).
- **Шалгасан:** `gofmt`, `go vet`, `go test ./...` (eidlogin 3 удаа), `GOOS=linux go build`.
- **Үлдсэн:** CA discovery-д `sessionTtl` (CA MR) deploy болтол push нь ажигласан утгаар (±1 с) ажиллана.
