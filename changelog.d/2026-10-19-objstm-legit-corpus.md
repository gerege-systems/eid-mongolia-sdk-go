### Tests — PRECHECKS #2b: хууль ёсны ObjStm баримтын хуурамч татгалзлын хамгаалалт

- **Юу:** `pades/testdata/objstm/` (qpdf 12.4.2 `--object-streams=generate`): Chrome 155 «Save as PDF» гаралт,
  linearized + ObjStm, гарын үсэгтэй хоёр (pdfcpu stamp, macOS-ийн eID гарын үсэгтэй баримт; бүтнээр дахин бичсэн тул
  зөвхөн бүтцийн шалгалтад). `TestObjStmLegitAccepted` — эдгээр ба `golden/input/{quartz,desktop}-objstm.pdf`-д
  `CheckStructure` зөвшөөрнө; гарын үсэггүйд `ValidatePDF` → `PDF_NO_SIGNATURE`, `Prepare` амжилттай. Шинэ файлууд
  `FuzzValidatePDF`-ийн seed болно.
- **Яагаад:** #2b-ийн ObjStm мөчлөгийн дүрэм бодит ObjStm-тэй баримтыг татгалзахгүйг батлах.
- **Шалгасан:** 6 файл бүгд ObjStm агуулагчийн шалгалтын замаар явсныг (түр `len(containers) > 0 → ErrStructure`
  болгоход 6 бүгд унасан) баталсан; дүрэм өөрчлөгдөөгүй; fuzz 2.5 мин олдворгүй.
