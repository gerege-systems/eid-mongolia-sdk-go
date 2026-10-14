### Клиент талын PAdES core (`pades`, `mobile`, `capi`, `wasm`)

- **Юу:** CA-ийн PAdES бичигч (`server/internal/pdfsign/pades/*`, баталгаажуулалтын хуудас + Noto Sans, TSA клиент,
  LTV цуглуулалт, нийтийн шалгагч `validate/*`)-ийг SDK-д extract хийв: `pades.Prepare` (хуудас → R_sig → DTBS),
  `pades.Complete` (гарын үсэг шалгах → RFC 3161 → CMS → OCSP/CRL → DSS → self-validation), `pades.Verify`.
  Binding: `mobile` (gomobile), `capi` (c-shared, `eid_pades_*` + `eid_free`), `wasm` (`globalThis.eidPades`).
- **Яагаад:** PDF eID-ийн серверт очихгүй (docs/PADES_CLIENT_SIDE.md, CA репо) — нэг Go core бүх платформд.
- **Хаана:** `pades/`, `pades/internal/{core,vpage,validate,eidcrypto,padestest}`, `mobile/`, `capi/`, `wasm/`,
  golden `pades/testdata/golden/`. `go.mod`: go 1.25 (pdfcpu v0.12.0-ийн шаардлага; өмнө 1.22), PDF/CMS хамаарлууд
  CA-тай ижил хувилбар; `tool` directive-ээр `golang.org/x/mobile/cmd/{gomobile,gobind}` (go 1.25-тай нийцэх 2026-08-13
  commit) — bind reproducible. CI: Go 1.25/stable, cross build, js/wasm тест (Node 22).
- **CA-аас зөрөх:** verify хуудасны /CreationDate = гарын үсгийн цаг (тодорхойлогдсон гаралт); шууд `/Info` trailer-т
  хуулагдана (профайл pades-client/1, P3); цуцлалтын төлөв DSS-ийн OCSP/CRL-ээс (CA DB-ээс); задлагч процесс дотор;
  pdfcpu-ийн тохиргоо config.yml-гүй (js/мобайл sandbox); OCSP/CRL сүлжээгээр (AIA/CDP), leaf-ийн OCSP thisUpdate > genTime
  хатуу (≤ 5 с давтана); өмнөх гарын үсэг eID-ийн хүчинтэй B-LT биш бол Prepare `PDF_FOREIGN_SIGNATURE` (CA: бүртгэлээр).
- **Шалгасан:** `go test -race ./...`, desktop-ийн Swift golden (quartz байт-ижил, objstm zlib-ээс бусад нь ижил),
  e2e (httptest TSA/OCSP/CRL), `GOOS=js GOARCH=wasm`, `-buildmode=c-shared`, linux/amd64.
