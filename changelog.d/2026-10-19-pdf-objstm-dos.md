### Security — `pades`: ObjStm мөчлөг ба /Size-аар процесс унах / гацах (fuzz олсон)

- **Юу:** `validate.CheckStructure` (Prepare / ValidatePDF / Verify / Complete-ийн урьдчилсан шалгалт) нь дараахыг
  `PDF_INVALID` (`Complete` — `STATE_INVALID`), `errors.Is(err, pades.ErrPDFStructure)` болгоно:
  - ObjStm доторх объектын агуулагч stream нь өөрөө ObjStm-д (өөрийгөө агуулах эсвэл харилцан мөчлөг);
  - ObjStm-ийн толгойн лавлагаа (`/Length` г.м.) ObjStm доторх объект руу заасан; `/Extends` мөчлөг / > 64 гинж;
  - trailer эсвэл xref stream-ийн `/Size` > 2 097 152.
  Өмнө нь ~8 KB баримт digitorus/pdf-ийн мөчлөгийн рекурсээр `fatal error: stack overflow` (recover барихгүй, процесс
  бүхэлдээ унана), `/Size 10000000000` — хязгааргүй давталт (Linux-д 400 GB хуваарилалт) өгдөг байв.
- **Яагаад:** `FuzzValidatePDF` эхний 4 секундэд олсон; v0.7.2-ийн давхарлалтын засвартай ижил ангиллын DoS.
- **Хаана:** `pades/internal/validate/objstm.go` (`checkObjStmGraph` — digitorus-ийн экспортлоогүй xref талбарыг
  reflect-ээр уншина; бүтэц өөрчлөгдвөл fail-closed), `nesting.go` (`/Size`), `pades/PRECHECKS.md` #2b.
- **Шалгасан:** `TestCheckStructureObjStmGraph` (хууль ёсны ObjStm + /Size = хязгаар задарна; 4 муу тохиолдол) — шалгалтыг
  түр унтраахад self / mutual / /Length тохиолдлууд `fatal error: stack overflow`, /Size 10^10 30 с timeout өгснийг
  баталсан; fuzz crash `pades/testdata/fuzz/FuzzValidatePDF/c8b2f6dc9d5d37bf` regression seed; `TestCheckStructureCorpus`
  (хуурамч татгалзалгүй).
- **Үлдсэн:** TS/Swift/Kotlin/.NET port-ууд PRECHECKS #2b-г давтах (задлагч нь мөчлөгт хамгаалалттай бол код л тааруулна).
