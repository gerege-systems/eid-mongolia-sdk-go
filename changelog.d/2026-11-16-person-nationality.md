### Added — `Person.Nationality`, `PersonSummary.Nationality` (иргэний харьяалал)

- **Юу:** `eid.Person.Nationality` (session-ий `person.nationality`) ба `eid.PersonSummary.Nationality` (`GET /v3/person/summary/etsi/{personEtsi}`-ийн `nationality`) — `string`, `omitempty`. Гурван том латин үсэг (ISO 3166-1 alpha-3, ICAO 9303; `MNG`, `USA`, `DEU`; `XXA` мэт ICAO тусгай код ч байж болно). Заавал биш: мэдэгдэхгүй бол `""`. Гэрчилгээний улс БИШ. SDK утгыг шалгахгүй, хэвээр дамжуулна. `Person` харьцуулагдах хэвээр (`*person == Person{}` — зөвхөн nationality-той person хоосон гэж тооцогдохгүй).
- **Яагаад:** CA хоёр хариунд нэмэлт заавал-биш `nationality` талбар нэмсэн; өмнө нь RP зөвхөн `Raw`-аар хүрдэг байсан. Нэмэлт өөрчлөлт тул MINOR (v0.28.0).
- **Хаана:** `types.go`, `person.go`; тест `portal_gaps_test.go` (`TestSessionPersonNationality`, `Summary` тест); README §person талбарын жагсаалт. `contract_test.go` person талбарыг тоочдоггүй тул өөрчлөөгүй.
- **Шалгасан:** локалд зөвхөн `gofmt -l`; `go vet`, `go test -race` — GitHub Actions CI.
