package validate

import (
	"bytes"
	"errors"
	"maps"
	"slices"
	"strings"
	"unicode/utf16"
)

// Гарын үсгийн ДАРАА нэмэгдсэн revision-ийн шинжилгээ.
//
// PAdES-д дараагийн гарын үсэг бүр incremental revision болж нэмэгддэг тул өмнөх гарын үсгийн
// ByteRange файлын төгсгөлд хүрэхгүй нь хэвийн. Гэвч яг ижил замаар агуулгыг сольж болно («shadow
// attack», incremental saving attack): халдагч харагдах агуулга нэмээд өөрийн хүчинтэй гарын үсгээр
// зурвал эхний гарын үсэг зурагч хараагүй зүйлдээ «хүчинтэй» гарч ирнэ. Тиймээс:
//
//   - суурь  = гарын үсгийн хамарсан муж дуусах хүртэлх баримт (doc[:end]),
//   - эцсийн = бүтэн файл,
//
// хоёрыг ЗАДАЛСАН объектын графаар харьцуулж, ялгаа бүр доорх зөвшөөрөгдсөн жагсаалтад багтвал л
// «зөвхөн гарын үсгээр өргөтгөгдсөн» гэж үзнэ. Бусад бүх зүйл — задарч чадаагүйг оруулаад —
// modified_after_signing хэвээр (fail closed).
//
// ХОЁР ГОРИМ (profile-ийг үз): prod нь зөвхөн profileOwnSigner — манай signing service-ийн нэмэлт гарын
// үсгийн яг хэлбэр. Доорх өргөн жагсаалт (profileBroad) нь түүний дээд хязгаар бөгөөд одоогоор зөвхөн тестээс
// хүрнэ; нарийн горим өргөн жагсаалтын БҮХ шалгалтыг давж, дээр нь өөрийн нэмэлт дүрмүүдийг хангах ёстой.
//
// Мужийн ард нэмэгдсэн xref хэсэг бүр нэг алхам: алхам БҮР өмнөх төлөвтэйгөө харьцуулахад доорх
// жагсаалтыг дангаараа давж (шинэ объект бүр — хүрэх эсэхээс үл хамааран — зөвшөөрөгдсөн үүрэгтэй),
// дээр нь суурь → эцсийн төлөв хуримтлагдсан байдлаараа давах ёстой (later()-ийг үз).
//
// Зөвшөөрөгдөх ялгаа:
//
//	Catalog      /AcroForm /DSS /Perms /Version-оос бусад түлхүүр (/Extensions ч мөн) бүтцээрээ ижил.
//	             Суурийн ижил дугаартай объект, эсвэл цоо шинэ объект (манай signer шинээр бичдэг).
//	             /Version зөвхөн өсөж болно («M.m», толгой ба суурийн Catalog-ийнхоос багагүй).
//	             /Perms-ийн мөр: шинэ гарын үсгийн толь, эсвэл суурийн /Perms-д яг тэр түлхүүрээр байсан объект.
//	AcroForm     /Fields ба /SigFlags-аас бусад бүх түлхүүр (/DA, /DR, /NeedAppearances, /XFA …) ижил.
//	             /Fields: суурийн мөрүүд дарааллаараа хэвээр, төгсгөлд нь зөвхөн шинэ гарын үсгийн талбар.
//	             /SigFlags: хэвээр, эсвэл 1 / 3 болж өснө (хасагдахгүй, буурахгүй).
//	Талбар       шинэ объект, /FT /Sig, зөвхөн sigFieldKeys түлхүүртэй (/A, /AA, /Kids, /MK … үгүй),
//	             /V нь шинэ гарын үсгийн толь руу заана (хоосон шинэ талбар үгүй). Эсвэл суурьт байсан
//	             ХООСОН гарын үсгийн widget (/Subtype нь Widget эсвэл байхгүй) бөглөгдөнө: зөвхөн /V,
//	             /AP, /M өөрчлөгдөнө. Шинэ widget-ийн /P: байхгүй, эсвэл хуудас (/Annots-д орсон бол тэр хуудас).
//	Sig толь     шинэ объект, /ByteRange + /Contents-тэй, stream биш, зөвхөн sigDictKeys түлхүүртэй;
//	             шууд бус заалт үгүй (ганц үл хамаарах: /Reference-ийн мөрийн /Data → Catalog). /Type нь
//	             Sig эсвэл байхгүй (DocTimeStamp үгүй), ByteRange = [0 a b c], нэг толийг нэг л талбар заана.
//	             Extract-ийн задалж шалгасан гарын үсгүүдийн нэг (ижил объект, ижил ByteRange) байх ёстой:
//	             хэн ч криптографаар шалгаагүй толь «дараагийн гарын үсэг»-т тооцогдохгүй.
//	Харагдах     талбарын /AP (шууд толь, /N /R /D → XObject) ба түүнээс хүрэх объектууд: бүгд ШИНЭ
//	гарын үсэг   объект, зөвхөн тэр дүрслэл дотроос л заагдсан байх ёстой. Зөвшөөрнө (PAdES-д хууль ёсны),
//	             гэхдээ хуудсан дээр зурах суваг тул visible_later_signature-аар мэдээлнэ.
//	Хуудас       хуудасны модоор (/Pages → /Kids) хүрэх /Type /Page объект. Цорын ганц ялгаа нь /Annots-ийн
//	             ТӨГСГӨЛД шинэ гарын үсгийн widget нэмэгдсэн байх (бусад түлхүүр, өмнөх annotation-ууд
//	             хэвээр; widget аль ч /Annots-д ганц удаа). Шууд бус /Annots массив: суурьт яг тэр хуудасны
//	             /Annots байсан, өөр хаанаас ч заагдаагүй. Өөр ямар ч толь, массив өөрчлөгдөхгүй.
//	DSS / VRI    толь, массив, шинэ сертификат/OCSP/CRL stream (LTV; толь нь зөвхөн /Length /Filter
//	             /DecodeParms, /Type-гүй). Эдгээр объект зөвхөн DSS-ийн бүтэц дотроос л заагдсан байх ёстой.
//	xref/trailer шинэ хэсэг бүр гарын үсгийн мужийн ард; /Info суурийнхтай яг ижил (орхигдохгүй, нэмэгдэхгүй),
//	             /ID-ийн эхний элемент ижил, /Size буураагүй, зөвхөн мэдэгдэж буй түлхүүр (/Encrypt,
//	             /XRefStm болон танихгүй түлхүүр үгүй).
//
// Нэмэлт шалгуур:
//   - суурьт ашиглагдаж байсан объект хожим чөлөөлөгдөөгүй (free), дугаар нь өөр утгаар дахин
//     тодорхойлогдоогүй; хожмын xref нь гарын үсгийн мужийн доторх байт руу заахгүй (нуусан объектыг
//     сэргээх), суурийн xref нь мужийн гадна руу заахгүй;
//   - мужийн ард байгаа байт бүр xref-т бүртгэлтэй объект, xref хэсэг, эсвэл зай (SP TAB CR LF FF; NUL,
//     тайлбар, бүртгэлгүй өгөгдөл үгүй); ObjStm доторх объект бүр xref-т бүртгэлтэй; classic xref-ийн
//     мөр яг 20 байт; нэмэгдсэн объект, xref хэсэг, trailer доторх токенуудын хооронд ч NUL, тайлбар үгүй;
//   - хуучин объектын хэлбэр (шууд ↔ ObjStm) болон үеийн дугаар солигдохгүй;
//   - байрлал 0 руу заасан «ашиглагдаж буй» мөр (macOS Quartz) = тодорхойлогдоогүй объект, free мөртэй ижил
//     (pdfobj.go useEnt): дээрх «чөлөөлөгдөөгүй», «сул заалт», «шинэ объектын үүрэг» дүрмүүд түүнд шууд хамаарна;
//   - суурийн аль ч объект суурьт байгаагүй дугаар руу заасан («сул» заалт) бөгөөд тэр дугаар хожим
//     тодорхойлогдсон бол үргэлж татгалзана;
//   - шинэ объект руу заасан заалт бүр зөвшөөрөгдсөн түлхүүрийн замаар байна: (эцэг, хүүхэд) хос бүрийн
//     бодит заалтын тоо зөвшөөрөгдсөн тоотой яг таарна;
//   - объект бүр ГАНЦ үүрэгтэй (classifier.role): нэг үүрэгт зөвшөөрөгдсөн нь өөр үүрэгт зөвшөөрөгдсөн гэсэн
//     үг биш; хуучин объект зөвхөн суурьт гүйцэтгэж байсан үүрэг/байрлалдаа л оролцоно;
//   - DSS-ээс өөр өөрчлөлттэй бол дор хаяж нэг шинэ гарын үсэг байх ёстой (гарын үсэггүй засвар үгүй).

var errNotSignatureOnly = errors.New("validate: гарын үсгийн дараах өөрчлөлт зөвшөөрөгдсөн жагсаалтад багтсангүй")

// sigFieldKeys — шинэ гарын үсгийн талбар/widget-д зөвшөөрөгдөх түлхүүрүүд.
var sigFieldKeys = []string{"Type", "Subtype", "FT", "T", "TU", "V", "Rect", "P", "F", "Ff", "M", "AP"}

// sigDictKeys — шинэ гарын үсгийн тольд зөвшөөрөгдөх түлхүүрүүд (ISO 32000-1 Table 252). Өөр түлхүүр
// (/S, /JS, /AA …) байвал толь өөр үүрэгт (үйлдэл г.м.) ашиглагдаж болно. /TransformMethod ба
// /TransformParams нь стандартаар /Reference-ийн мөр дотор байх ёстой боловч digitorus/pdfsign (манай
// signer) approval гарын үсэгт тэдгээрийг Sig толийн дээд түвшинд бичдэг тул жагсаалтад орсон (шууд утга).
var sigDictKeys = []string{"Type", "Filter", "SubFilter", "Contents", "ByteRange", "Cert", "M", "Name", "Location", "Reason",
	"ContactInfo", "Reference", "Prop_Build", "Prop_AuthTime", "Prop_AuthType", "Changes", "R", "V",
	"TransformMethod", "TransformParams"}

// profile — «зөвхөн гарын үсгээр өргөтгөгдсөн» гэж юуг үзэх вэ.
//
// Гурван удаагийн бие даасан review бүр өргөн жагсаалтаас бодит цоорхой олсон тул prod нь НАРИЙН горимоор
// ажиллана; өргөн жагсаалт кодод үлдэх боловч гадны signer-ийн бодит гаралтаар шалгагдах хүртэл prod-оос
// хүрэх боломжгүй (зөвхөн тестээс). Энэ нь env/тохиргоо биш — кодын тогтмол.
type profile uint8

const (
	// profileOwnSigner (анхдагч, тэг утга; Extract-ийн хэрэглэдэг ганц горим) — нэмэгдсэн revision бүр манай
	// signing service (internal/pdfsign → digitorus/pdfsign, go.mod-д бэхлэгдсэн хувилбар)-ийн нэмэлт approval
	// гарын үсэгт бичдэг ЯГ тэр хэлбэртэй байх ёстой:
	//   - шинэ объект: нэг Sig толь (/Type /Sig, ownSigDictKeys), нэг ҮЛ ХАРАГДАХ талбар/widget (ownFieldKeys,
	//     /Rect [0 0 0 0], /F 132, /AP-гүй) ЭСВЭЛ PAdES бичигчийн ХАРАГДАХ widget + /AP-ийн 11 объект (pades/APPEARANCE_SPEC.md
	//     §5 — дахин үүсгэж байт-түвшинд тулгана, appearance.go), ШИНЭ дугаартай Catalog (digitorus Catalog-ийг үргэлж шинэ
	//     объектоор бичдэг; хуучин нь өнчирнө), xref stream-тэй суурьт xref stream объект (өөрийгөө Index-д
	//     бүртгэсэн эсвэл үгүй). Өөр юу ч үгүй;
	//   - Catalog: /AcroForm (шууд толь, яг /Fields = өмнөх талбарууд + шинэ нэг талбар, /SigFlags 3) ба
	//     /Version (зөвхөн суурьт байхгүй, толгой 1.5-аас доош үед нэмэгдэх /1.5)-оос бусад түлхүүр ижил;
	//   - хуучин объект өөрчлөгдөхгүй, ижил утгаар ч дахин бичигдэхгүй: нэмэгдсэн xref-ийн мөр бүр суурьт
	//     ашиглагдаагүй дугаартай шинэ объект, free мөр үгүй («ижил утга» нь манай задлагчийн уншилт, viewer-ийнх
	//     биш). Ганц үл хамаарах: PAdES бичигч widget-ийг хуудасны /Annots-ийн төгсгөлд нэмэхдээ тэр хуудсыг (эсвэл
	//     түүний шууд бус /Annots массивыг) ижил дугаараар бичнэ — page()-ийн дүрмээр зөвхөн /Annots өөрчлөгдсөн;
	//   - бичвэрүүд digitorus-ийн бичдэг хэлбэртэй (ownText): талбарын /T нь ASCII «Signature N», суурийн болон
	//     бусад шинэ талбарын нэртэй давхцахгүй; Sig толийн /Name /Reason /Location /ContactInfo нь ≤ 256 байт,
	//     ASCII эсвэл BOM-той UTF-16BE, удирдах тэмдэгт (NUL/CR/LF …) болон PDF-ийн бүтцийн түлхүүр үггүй
	//     (ownTextForbidden); /M нь яг «D:YYYYMMDDHHmmSS±HH'mm'»;
	//   - revision бүрд яг нэг гарын үсэг; гарын үсэггүй revision, /DSS /VRI (LTV), /Perms, /Extensions,
	//     APPEARANCE_SPEC-ээс өөр /AP ба харагдах widget, бөглөгдсөн хуучин талбар, DocTimeStamp, нэмэгдсэн ObjStm — бүгд татгалзана;
	//   - trailer-ийн /Info: суурийнхтай ижил, эсвэл xref STREAM хэсэгт орхигдсон (digitorus xref stream-ийн
	//     толинд /Info бичдэггүй; classic trailer-т хуулдаг тул тэнд орхихыг зөвшөөрөхгүй).
	// Тиймээс энэ горимд visible_later_signature нь зөвхөн APPEARANCE_SPEC-ийн харагдах гарын үсэгт үнэн, later_signatures
	// нь revision-ийн тоо.
	profileOwnSigner profile = iota
	// profileBroad — энэ файлын толгойд тайлбарласан өргөн жагсаалт (харагдах гарын үсэг, LTV, /Perms,
	// бөглөгдсөн талбар, хуудасны /Annots …). Зөвхөн тестээс.
	profileBroad
)

// ownFieldKeys / ownSigDictKeys — digitorus/pdfsign-ийн approval гарын үсэгт бичдэг түлхүүрүүд
// (sign/pdfvisualsignature.go, sign/pdfsignature.go).
var (
	ownFieldKeys   = []string{"Type", "Subtype", "Rect", "P", "F", "FT", "T", "V"}
	ownSigDictKeys = []string{"Type", "Filter", "SubFilter", "Prop_Build", "ByteRange", "Contents", "TransformMethod",
		"TransformParams", "Name", "Location", "Reason", "ContactInfo", "M"}
)

// padesSigDictKeys — PAdES бичигчийн (internal/pdfsign/pades) Sig толийн түлхүүрүүд.
var padesSigDictKeys = []string{"Type", "Filter", "SubFilter", "ByteRange", "Contents", "M", "Name", "Reason"}

// ownTextLimit — Sig толийн чөлөөт бичвэрийн (/Name /Reason /Location /ContactInfo /M) дээд урт, байтаар.
const ownTextLimit = 256

// ownTextForbidden — PDF-ийн бүтцийн түлхүүр үгс. Бичвэр дотор эдгээр байвал xref-ийг файлаас хайж сэргээдэг
// viewer тэндээс объект/xref «олж» болзошгүй тул манай signer-ийн бичвэрт (түүхий байт болон тайлсан бичвэр
// аль алинд) байх ёсгүй.
var ownTextForbidden = []string{" obj", "endobj", "stream", "xref", "trailer", "startxref", "%%EOF"}

// pdfTextString — PDF text string-ийг тайлна: BOM-той (FE FF) бол UTF-16BE, эс бөгөөс байт бүр нэг тэмдэгт.
func pdfTextString(s pdfStr) string {
	raw := string(s)
	if !strings.HasPrefix(raw, "\xfe\xff") {
		return raw
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 2; i+1 < len(raw); i += 2 {
		units = append(units, uint16(raw[i])<<8|uint16(raw[i+1]))
	}
	return string(utf16.Decode(units))
}

// ownText — v нь digitorus-ийн pdfString-ийн бичдэг хэлбэртэй бичвэр мөн эсэх; тайлсан бичвэрийг буцаана.
// digitorus ASCII бичвэрийг шууд, бусдыг BOM-той UTF-16BE-ээр (literal string дотор түүхий байтаар) бичдэг —
// UTF-16BE-ийн байтууд 0x00, 0x0A зэргийг хууль ёсоор агуулж болох тул удирдах тэмдэгтийг ТАЙЛСАН бичвэр дээр
// шалгана: аль ч хэлбэрт NUL, CR, LF болон бусад удирдах тэмдэгт, бүтцийн түлхүүр үг байхгүй.
func ownText(v any, limit int) (string, bool) {
	s, ok := v.(pdfStr)
	if !ok || len(s) > limit {
		return "", false
	}
	raw := string(s)
	utf16be := strings.HasPrefix(raw, "\xfe\xff")
	if utf16be && len(raw)%2 != 0 {
		return "", false
	}
	text := pdfTextString(s)
	for _, r := range text {
		if r < 0x20 || r == 0x7f || !utf16be && r > 0x7e {
			return "", false
		}
	}
	for _, bad := range ownTextForbidden {
		if strings.Contains(raw, bad) || strings.Contains(text, bad) {
			return "", false
		}
	}
	return text, true
}

// ownFieldName — «Signature N», N = 1…9999 (тэргүүн тэггүй).
func ownFieldName(s string) bool {
	n, ok := strings.CutPrefix(s, "Signature ")
	if !ok || len(n) < 1 || len(n) > 4 || n[0] == '0' {
		return false
	}
	return strings.Trim(n, "0123456789") == ""
}

// ownDate — «D:YYYYMMDDHHmmSS±HH'mm'» (digitorus pdfDateTime; Z хэлбэр бичдэггүй).
func ownDate(s string) bool {
	if len(s) != 23 || s[:2] != "D:" || s[16] != '+' && s[16] != '-' || s[19] != '\'' || s[22] != '\'' {
		return false
	}
	return strings.Trim(s[2:16]+s[17:19]+s[20:22], "0123456789") == ""
}

// LaterChanges — гарын үсгийн мужийн дараах revision-уудын дүгнэлт.
type LaterChanges struct {
	// SignaturesOnly — бүх ялгаа зөвшөөрөгдсөн жагсаалтад багтсан. false бол бусад талбар 0/false.
	SignaturesOnly bool
	Signatures     int  // шинээр нэмэгдсэн гарын үсэг / баримтын цагийн тэмдгийн тоо
	Visible        bool // аль нэг шинэ гарын үсгийн widget хоосон биш /Rect эсвэл /AP-тэй
}

// revisions — нэг баримтын бүх гарын үсэгт хуваалцах төлөв: харагдац (эхний N байт) ба алхмын дүнгийн кэш.
type revisions struct {
	doc    []byte
	budget *pdfBudget
	views  map[int]*pdfView // уртаар; задраагүй бол nil
	steps  map[[3]int]*LaterChanges
	// known — Extract-ийн задалж, криптографаар шалгасан гарын үсгүүд: объектын дугаар → ByteRange.
	// Ангилагч «дараагийн гарын үсэг» гэж тоолох толь бүр энд байх ёстой: хэн ч шалгаагүй толь
	// (жишээ нь Extract-ийн алгасдаг /Type /DocTimeStamp) гарын үсэгт тооцогдохгүй.
	known   map[int][]int64
	profile profile
	// sigs — known-ийн гарын үсэг бүрийн харагдах дүрслэлийн өгөгдөл (appearance.go); docID — баримтын verify
	// хуудасны холбоосын UUID ("" — хуудасгүй).
	sigs  map[int]sigMeta
	docID string
}

func newRevisions(doc []byte, known map[int][]int64, p profile) *revisions {
	return &revisions{doc: doc, budget: newPDFBudget(), views: map[int]*pdfView{}, steps: map[[3]int]*LaterChanges{}, known: known, profile: p}
}

func (r *revisions) view(n int) *pdfView {
	v, ok := r.views[n]
	if !ok {
		v, _ = openView(r.doc[:n], r.budget)
		r.views[n] = v
	}
	return v
}

// later — end (ByteRange-ийн төгсгөл)-ээс хойшхи өөрчлөлтийг ангилна. Алдаа, panic бүр «зөвшөөрөгдөөгүй».
//
// Мужийн ард нэмэгдсэн xref хэсэг бүр нэг алхам. (1) Алхам БҮР өмнөх төлөвтэйгөө харьцуулахад
// зөвшөөрөгдсөн жагсаалтыг дангаараа (хатуу горимоор) давах ёстой — дараагийн алхам «буцааж» дарсан
// завсрын тодорхойлолт ч файлд үлддэг тул нийлүүлсэн xref-ээр «өөрчлөгдөөгүй» харагдах нь хангалтгүй.
// (2) Суурь → эцсийн төлөв хуримтлагдсан байдлаараа мөн давах ёстой.
func (r *revisions) later(end int64) (out LaterChanges) {
	defer func() {
		if recover() != nil {
			out = LaterChanges{}
		}
	}()
	n := len(r.doc)
	if end <= 0 || end >= int64(n) {
		return LaterChanges{}
	}
	final, base := r.view(n), r.view(int(end))
	if final == nil || base == nil {
		return LaterChanges{}
	}
	k := len(final.sections) - len(base.sections)
	if k < 1 {
		return LaterChanges{}
	}
	ends := []int{int(end)}
	for i := k - 1; i >= 0; i-- {
		s := final.sections[i]
		p := final.parser(s.end)
		at, ok := p.startxref()
		e := p.pos
		if i == 0 {
			e = n
		}
		if !ok || at != s.off || e <= ends[len(ends)-1] {
			return LaterChanges{}
		}
		ends = append(ends, e)
	}
	out.SignaturesOnly = true
	sigSteps := 0
	for i := 1; i < len(ends); i++ {
		hasSig := r.hasSig(ends[i-1], ends[i])
		if hasSig {
			sigSteps++
		}
		st := r.classify(ends[i-1], ends[i], true, r.stepMode(hasSig))
		if st == nil {
			return LaterChanges{}
		}
		out.Signatures += st.Signatures
		out.Visible = out.Visible || st.Visible
	}
	if k > 1 {
		// Алхмуудын нийлбэр ба хуримтлагдсан харьцуулалт ижил тооны гарын үсэг олох ёстой. Хуримтлагдсан
		// горим: бүх алхам гарын үсэгтэй → алхмын горим; бүгд DSS-only → DSS-only; холимог (PAdES: R_sig,
		// R_dss ээлжилнэ) → өргөн жагсаалт (алхам бүр аль хэдийн өөрийн нарийн горимоор шалгагдсан).
		mode := modeBroad
		switch sigSteps {
		case k:
			mode = r.stepMode(true)
		case 0:
			mode = r.stepMode(false)
		}
		cum := r.classify(ends[0], n, false, mode)
		if cum == nil || cum.Signatures != out.Signatures {
			return LaterChanges{}
		}
		out.Visible = out.Visible || cum.Visible
	}
	return out
}

// stepMode — алхмын ангиллын горим: гарын үсэгтэй алхамд profile-ийн горим (own → манай signer-ийн яг
// хэлбэр), гарын үсэггүй алхамд DSS-only (LTV өгөгдөл — манай R_dss ба гадны хэрэгслийн «Add verification
// information», docs/PADES_SIGNING.md §8.2, шийдвэр 10-07 Q7) — хоёр profile-д ижил.
func (r *revisions) stepMode(hasSig bool) classifyMode {
	switch {
	case !hasSig:
		return modeDSSOnly
	case r.profile == profileOwnSigner:
		return modeOwn
	}
	return modeBroad
}

// hasSig — Extract-ийн шалгасан гарын үсгийн толь (объектын дугаараар) энэ алхамд шинээр тодорхойлогдсон
// эсэх: тэр алхам гарын үсэг нэмсэн. Ангилагч тэр гарын үсгийг өөрөө дахин тулгана (sigValue); шалгагдаагүй
// гарын үсэг мэт объекттой алхам DSS-only горимд орж татгалзагдана. Задраагүй харагдацыг гарын үсэгтэй гэж
// үзнэ (горим нь илүү хатуу; classify өөрөө татгалзана).
func (r *revisions) hasSig(from, to int) bool {
	base, fin := r.view(from), r.view(to)
	if base == nil || fin == nil {
		return true
	}
	for num := range r.known {
		if fin.xref[num].inUse() && !base.xref[num].inUse() {
			return true
		}
	}
	return false
}

// classifyMode — нэг шилжилтийн ангиллын горим.
type classifyMode uint8

const (
	modeBroad   classifyMode = iota // өргөн жагсаалт
	modeOwn                         // манай signer-ийн яг хэлбэр (profileOwnSigner)
	modeDSSOnly                     // гарын үсэггүй: зөвхөн DSS/VRI (+ мэдээллийн /Info, XMP, /Extensions)
)

// classify — doc[:from] → doc[:to] шилжилтийг ангилна; зөвшөөрөгдөөгүй бол nil.
func (r *revisions) classify(from, to int, strict bool, mode classifyMode) *LaterChanges {
	key := [3]int{from, to, int(mode) * 2}
	if strict {
		key[2]++
	}
	if res, ok := r.steps[key]; ok {
		return res
	}
	var res *LaterChanges
	if base, fin := r.view(from), r.view(to); base != nil && fin != nil {
		c := newClassifier(base, fin, strict, r.known)
		c.sigs, c.docID = r.sigs, r.docID
		c.own, c.dssOnly, c.ownProfile = mode == modeOwn, mode == modeDSSOnly, r.profile == profileOwnSigner
		if c.run() == nil {
			res = &LaterChanges{SignaturesOnly: true, Signatures: len(c.sigDicts), Visible: c.visible}
		}
	}
	r.steps[key] = res
	return res
}

type classifier struct {
	base, fin *pdfView
	end       int
	// strict — нэг алхмын горим: ШИНЭ объект бүр (хүрэх эсэхээс үл хамааран) зөвшөөрөгдсөн үүрэгтэй байх
	// ёстой. Хуримтлагдсан горимд өмнөх алхмын өнчин объект (жишээ нь дарагдсан Catalog) хэвийн тул
	// зөвхөн trailer-ээс хүрэх объектыг шалгана — тэдгээр нь өөрийн алхамдаа хатуу горимоор шалгагдсан.
	strict bool
	// own — profileOwnSigner: зөвшөөрөгдсөн жагсаалтын дээр манай signer-ийн яг хэлбэрийг шаардана.
	own bool
	// dssOnly — гарын үсэггүй алхам: өргөн жагсаалтын DSS дүрэм + зөвхөн LTV/мэдээллийн объект өөрчлөгдөнө
	// (гарын үсэг, талбар, хуудас, /Perms үгүй). /Version, /Extensions (шууд, заалтгүй), /Info (бичвэр), XMP
	// /Metadata нь зөвхөн DSS-ийг бодитоор өөрчилсөн алхамд (гадны хэрэгсэл хадгалахдаа шинэчилдэг).
	dssOnly bool
	// ltvWork — DSS-ийн бүтэц (толь/массив/stream) шинэ эсвэл өөрчлөгдсөн; infoWork — /Version /Extensions
	// /Info /Metadata өөрчлөгдсөн (dssOnly-д зөвхөн ltvWork-тэй хамт).
	ltvWork, infoWork bool
	// ownProfile — prod-ийн profileOwnSigner: DSS-only алхам DSS-ийг заавал өөрчилнө (хоосон revision үгүй),
	// хуучин объектыг ижил утгаар дахин бичихгүй. profileBroad (зөвхөн тест) эдгээрийг шаардахгүй — own ⊆ broad.
	ownProfile bool
	// rewritten — dssOnly: суурьт ашиглагдаж байсан дугаарыг шинэ хэсэгт дахин тодорхойлсон. Ийм объект бүр
	// бодитоор өөрчлөгдсөн, зөвшөөрөгдсөн LTV/мэдээллийн үүрэгтэй байх ёстой — «ижил утгаар дахин бичсэн» нь
	// манай задлагчийн уншилтаар л ижил (viewer өөрөөр уншиж болно) тул хүлээн авахгүй.
	rewritten map[int]bool
	// ownRewrite — own: суурьт ашиглагдаж байсан дугаарыг шинэ хэсэгт дахин бичсэн (зөвхөн хуудас / /Annots).
	ownRewrite map[int]bool
	root       int          // эцсийн Catalog-ийн дугаар
	changed    map[int]bool // суурьтай харьцуулахад шинэ эсвэл өөр утгатай объект
	isNew      map[int]bool // суурьт ашиглагдаагүй дугаар
	allowed    map[int]bool // зөвшөөрөгдсөн үүрэгт таарсан өөрчлөлт
	exclusive  map[int]bool // зөвхөн edges-д бүртгэгдсэн заалтаар л заагдах ёстой (шинэ объект, DSS-ийн сав)
	infra      map[int]bool // xref stream, ObjStm — файлын бүтцийн объект; хэн ч заахгүй
	xrefSelf   map[int]bool // xref stream-ийн өөрийгөө бүртгэсэн мөр (infra-ийн дэд олонлог, ObjStm биш)
	// edges — (эцэг, хүүхэд) хос бүрд ЗӨВШӨӨРӨГДСӨН заалтын тоо. Эцэг объект доторх бодит заалтын тоо
	// үүнтэй яг таарах ёстой: зөвшөөрөгдсөн түлхүүрийн замаас гадуурх нэмэлт заалт бүр илүүдэл болж баригдана.
	edges    map[[2]int]int
	sigDicts map[int]bool
	widgets  map[int]bool
	// role — объект бүрийн авсан ГАНЦ үүрэг (catalog, acroform, fields, field, sig, ap, page, annots, perms,
	// dss, vri, vrient, ltvarr, ltv). Нэг үүрэгт зөвшөөрөгдсөн нь өөр үүрэгт зөвшөөрөгдсөн гэсэн үг биш:
	// хоёр үүрэг авах гэвэл татгалзана (claim).
	role map[int]string
	// seen — элементүүд/дэд мод нь нэгэнт ангилагдсан объект. Зөвхөн ИЖИЛ үүргээр дахин орж ирэхэд
	// (жишээ нь /Certs ба VRI-ийн заасан нэг массив) давхар тоолохгүйн тулд; шалгалтыг алгасахад биш.
	seen       map[int]bool
	known      map[int][]int64 // revisions.known
	pages      map[int]bool    // эцсийн хуудасны модны /Type /Page объектууд
	widgetP    map[int]int     // шинэ widget → /P-ийн заасан хуудас (байхгүй бол 0)
	widgetPage map[int]int     // шинэ widget → /Annots-д нь орсон хуудас
	annotsOf   map[int]int     // шууд бус /Annots массив → эзэн хуудас
	fieldNames map[string]bool // own: суурийн болон шинэ талбаруудын /T
	visible    bool
	// ownVis — own: APPEARANCE_SPEC-ийн яг хэлбэрээр шалгагдсан харагдах widget-ууд (/P хуудасны /Annots-д заавал).
	ownVis  map[int]bool
	sigs    map[int]sigMeta
	docID   string
	sigWork bool // DSS-ээс өөр (гарын үсэгтэй холбоотой) өөрчлөлт орсон
}

func newClassifier(base, fin *pdfView, strict bool, known map[int][]int64) *classifier {
	return &classifier{base: base, fin: fin, end: len(base.b), strict: strict, known: known,
		changed: map[int]bool{}, isNew: map[int]bool{}, allowed: map[int]bool{}, exclusive: map[int]bool{},
		infra: map[int]bool{}, xrefSelf: map[int]bool{}, edges: map[[2]int]int{}, sigDicts: map[int]bool{}, widgets: map[int]bool{},
		role: map[int]string{}, seen: map[int]bool{}, pages: map[int]bool{}, widgetP: map[int]int{},
		widgetPage: map[int]int{}, annotsOf: map[int]int{}, fieldNames: map[string]bool{}, rewritten: map[int]bool{},
		ownRewrite: map[int]bool{}, ownVis: map[int]bool{}}
}

// claim — num объектыг role үүрэгт бүртгэнэ; өөр үүрэг аль хэдийн авсан бол алдаа.
func (c *classifier) claim(num int, role string) error {
	if r, ok := c.role[num]; ok && r != role {
		return errNotSignatureOnly
	}
	c.role[num] = role
	return nil
}

func (c *classifier) run() error {
	if err := c.structure(); err != nil {
		return err
	}
	if err := c.diff(); err != nil {
		return err
	}
	refs, err := c.fin.graph()
	if err != nil {
		return err
	}
	// Эцсийн trailer-ээс хүрэх объектууд. ref бүрийг дагадаг тул аль ч viewer-ийн үзэх хүрээг агуулна.
	reach := map[int]bool{}
	var queue []int
	pdfRefs(c.fin.trailer, func(r pdfRef) { queue = append(queue, r.num) })
	for len(queue) > 0 {
		n := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if reach[n] || !c.fin.xref[n].inUse() {
			continue
		}
		reach[n] = true
		queue = append(queue, refs[n]...)
	}
	for n := range c.isNew {
		if c.strict || reach[n] {
			c.exclusive[n] = true
		}
	}
	// Суурийн «сул» заалт: суурийн объект (хаана ч байсан) суурьт байгаагүй дугаар руу заасан бөгөөд тэр
	// дугаар хожим тодорхойлогдсон бол гарын үсэг зурагчийн хараагүй зүйл идэвхжинэ — үргэлж татгалзана.
	dangling := false
	isNew := func(r pdfRef) { dangling = dangling || c.isNew[r.num] }
	pdfRefs(c.base.trailer, isNew)
	for num, e := range c.fin.xref {
		switch {
		case !e.inUse() || c.isNew[num]:
		case c.changed[num]:
			bo, err := c.base.get(num)
			if err != nil {
				return err
			}
			pdfRefs(bo, isNew)
		default: // өөрчлөгдөөгүй: эцсийн заалтууд = суурийн заалтууд
			for _, to := range refs[num] {
				dangling = dangling || c.isNew[to]
			}
		}
	}
	if dangling {
		return errNotSignatureOnly
	}
	if err := c.catalog(); err != nil {
		return err
	}
	// Хуудсууд (дугаарын дарааллаар — дүн map-ийн дарааллаас хамаарахгүй): цорын ганц зөвшөөрөгдөх ялгаа
	// нь /Annots-ийн төгсгөлд шинэ гарын үсгийн widget.
	for _, p := range slices.Sorted(maps.Keys(c.pages)) {
		if err := c.page(p); err != nil {
			return err
		}
	}
	// own: ижил дугаараар дахин бичсэн хуучин объект бүр өөрчлөгдсөн, зөвшөөрөгдсөн хуудас / /Annots массив
	// (ижил утгаар дахин бичихгүй — «ижил» нь манай задлагчийн уншилт, viewer-ийнх биш).
	for n := range c.ownRewrite {
		if !c.changed[n] || !c.allowed[n] || c.role[n] != "page" && c.role[n] != "annots" {
			return errNotSignatureOnly
		}
	}
	// Шинэ widget-ийн /P: байхгүй, эсвэл /Annots-д нь орсон хуудас (аль ч /Annots-д ороогүй бол дурын хуудас).
	for w, p := range c.widgetP {
		if at, placed := c.widgetPage[w]; p != 0 && (!c.pages[p] || placed && at != p) || c.ownVis[w] && (!placed || at != p) {
			return errNotSignatureOnly
		}
	}
	if c.dssOnly {
		if err := c.info(); err != nil {
			return err
		}
	}
	// Үлдсэн өөрчлөгдсөн объект бүр зөвшөөрөгдөөгүй.
	for n := range c.changed {
		if !c.allowed[n] && !c.infra[n] && (c.strict || reach[n]) {
			return errNotSignatureOnly
		}
		// Манай signer хуучин объектоос зөвхөн widget нэмсэн хуудас / түүний /Annots массивыг дахин бичнэ
		// (Catalog хүртэл шинэ дугаартай).
		if c.own && !c.isNew[n] && !(c.allowed[n] && (c.role[n] == "page" || c.role[n] == "annots")) {
			return errNotSignatureOnly
		}
	}
	if c.dssOnly {
		if err := c.dssOnlyRules(); err != nil {
			return err
		}
	}
	if c.own {
		// Алхам бүр: яг нэг гарын үсэг + нэг талбар + шинэ Catalog (+ xref stream). Хуримтлагдсан горимд
		// алхмуудын нийлбэр тул зөвхөн «дор хаяж нэг» ба «гарын үсэг = талбар».
		if !c.isNew[c.root] || len(c.sigDicts) != len(c.widgets) || len(c.sigDicts) == 0 || c.strict && len(c.sigDicts) != 1 ||
			c.visible && len(c.ownVis) == 0 {
			return errNotSignatureOnly
		}
		// Шинэ объект: зөвхөн Sig толь, талбар, Catalog. ObjStm бичдэггүй; xref stream-ийг digitorus бүртгэдэггүй
		// байсан, PAdES бичигч (2026-10-07-оос) өөрийгөө бүртгэдэг — тэр мөрөөс өөр файлын бүтцийн шинэ объект
		// (infra) байх ёсгүй.
		for n := range c.isNew {
			if r := c.role[n]; c.strict && !c.xrefSelf[n] && r != "sig" && r != "field" && r != "catalog" && (r != "ap" || len(c.ownVis) == 0) {
				return errNotSignatureOnly
			}
		}
	}
	// Онцгой объект руу заасан заалт бүр зөвшөөрөгдсөн байх ёстой (тоогоороо яг таарна).
	for from, tos := range refs {
		// xref stream / ObjStm нь баримтын графын хэсэг биш (xref stream-ийн толь = trailer, доор шалгагдана).
		if !c.strict && !reach[from] || c.infra[from] {
			continue
		}
		count := map[int]int{}
		for _, to := range tos {
			if c.exclusive[to] {
				count[to]++
			}
		}
		for to, n := range count {
			if c.edges[[2]int{from, to}] != n {
				return errNotSignatureOnly
			}
		}
	}
	bad := false
	for k, v := range c.fin.trailer {
		if k != "Root" {
			pdfRefs(v, func(r pdfRef) { bad = bad || c.exclusive[r.num] })
		}
	}
	if bad || len(c.sigDicts) == 0 && c.sigWork {
		return errNotSignatureOnly
	}
	return nil
}

// structure — xref гинж, trailer, мужийн дараах байтуудын бүрэн хамралт.
func (c *classifier) structure() error {
	fs, bs := c.fin.sections, c.base.sections
	k := len(fs) - len(bs)
	if k < 1 || c.strict && k != 1 {
		return errNotSignatureOnly
	}
	// Эцсийн гинж суурийн гинжээр ЯГ үргэлжлэх ёстой (суурийн сүүлийн xref-ийг алгасаж болохгүй).
	for i, s := range bs {
		if fs[k+i].off != s.off {
			return errNotSignatureOnly
		}
	}
	// Linearized баримтын /L нь ЭЦСИЙН файлын урттай таарвал зарим viewer эхний хуудсыг гарын үсгийн
	// мужийн доторх «хурдан» xref-ээр (өөр объектоор) зурж болно — урьдчилан бэлдсэн заль гэж үзнэ.
	lin := c.fin.parser(0)
	lin.skip()
	if o, err := lin.indirect(nil); err == nil {
		if d, ok := o.val.(pdfDict); ok && d["Linearized"] != nil && d["L"] == int64(len(c.fin.b)) {
			return errNotSignatureOnly
		}
	}
	var spans [][2]int
	for _, s := range fs[:k] {
		// Манай signer-ийн ганц гажилт: xref stream-ийн толинд /Info бичдэггүй (profileOwnSigner-ийг үз).
		infoOmitted := c.own && s.trailer["Type"] == pdfName("XRef") && s.trailer["Info"] == nil
		if s.off < c.end || !trailerCompatible(c.base.trailer, s.trailer, infoOmitted) {
			return errNotSignatureOnly
		}
		p := c.fin.parser(s.end)
		if at, ok := p.startxref(); !ok || at != s.off {
			return errNotSignatureOnly
		}
		spans = append(spans, [2]int{s.start, p.pos})
		// Хэсгийн өөрийнх нь бичлэг: classic бол «xref … trailer <<…>>» дотор NUL, тайлбар (%) байхгүй,
		// trailer-т зөвхөн мэдэгдэж буй түлхүүр; xref stream бол объектыг хатуу горимоор дахин задална.
		keys := []string{"Size", "Root", "Info", "ID", "Prev"}
		if c.fin.b[s.start] == 'x' {
			if bytes.ContainsAny(c.fin.b[s.start:s.end], "\x00%") {
				return errNotSignatureOnly
			}
		} else {
			keys = append(keys, "Type", "W", "Index", "Length", "Filter", "DecodeParms")
			sp := c.fin.parser(s.start)
			sp.strict = true
			if _, err := sp.indirect(nil); err != nil {
				return err
			}
		}
		if !onlyKeys(s.trailer, keys...) {
			return errNotSignatureOnly
		}
		packed := map[int]int{} // ObjStm-ийн дугаар → энэ хэсэгт бүртгэгдсэн доторх объектын тоо
		for num, e := range s.ents {
			// Манай signer хуучин объектыг хэзээ ч дахин бичдэггүй, free мөр ч бичдэггүй: нэмэгдсэн xref-ийн
			// мөр бүр суурьт ашиглагдаагүй дугаартай шинэ объект байх ёстой. «Ижил утгаар дахин бичсэн» нь
			// манай задлагчийн тайлбараар л ижил — viewer өөрөөр уншиж болох тул зөвшөөрөхгүй.
			// Ганц үл хамаарах: PAdES бичигч widget-ийг хуудасны /Annots-д нэмэхийн тулд тэр хуудсыг (эсвэл
			// түүний шууд бус /Annots массивыг) ижил дугаараар дахин бичнэ — run() үүргийг нь (page/annots,
			// өөрчлөгдсөн, зөвшөөрөгдсөн) шалгана.
			if c.own && e.kind != entUse {
				return errNotSignatureOnly
			}
			if c.own && c.base.xref[num].inUse() {
				c.ownRewrite[num] = true
			}
			if c.dssOnly && c.ownProfile && e.inUse() && c.base.xref[num].inUse() {
				c.rewritten[num] = true
			}
			switch e.kind {
			case entUse:
				// Объект яг бүртгэгдсэн байрлалаас (цифрээр) эхэлнэ: урд нь NUL/зай нуухгүй.
				if e.off < c.end || e.off >= len(c.fin.b) || c.fin.b[e.off] < '0' || c.fin.b[e.off] > '9' {
					return errNotSignatureOnly
				}
				if e.off == s.start { // xref stream өөрийгөө бүртгэсэн
					c.infra[num], c.xrefSelf[num] = true, true
					continue
				}
				// Хатуу горим: объект доторх токенуудын хооронд ч NUL, тайлбар байхгүй (тайлбар дотор нуусан
				// «N 0 obj»-г файлаас хайж сэргээдэг viewer олж болно).
				p := c.fin.parser(e.off)
				p.strict = true
				o, err := p.indirect(c.fin.length)
				if err != nil {
					return err
				}
				if o.num != num || o.gen != e.gen {
					return errNotSignatureOnly
				}
				spans = append(spans, [2]int{e.off, p.pos})
			case entComp:
				// Шахсан объект зөвхөн мужийн ард бичигдсэн ObjStm дотор байж болно.
				if st := c.fin.xref[e.off]; st.kind != entUse || st.off < c.end {
					return errNotSignatureOnly
				}
				if c.own { // манай signer нэмэгдсэн revision-д object stream бичдэггүй
					return errNotSignatureOnly
				}
				packed[e.off]++
			}
		}
		// Хатуу горимд (хэсэг нь хамгийн шинэ): ObjStm доторх объект БҮР xref-т бүртгэлтэй байх ёстой —
		// бүртгэлгүй «нуусан» объектыг файлаас хайж сэргээдэг viewer олж болно.
		for stm, n := range packed {
			if !c.strict {
				continue
			}
			st, err := c.fin.objStm(stm)
			if err != nil {
				return err
			}
			if _, here := s.ents[stm]; !here || len(st.nums) != n {
				return errNotSignatureOnly
			}
			for _, off := range st.offs { // доторх объект бүр хатуу горимоор (NUL, тайлбаргүй) задарна
				sp := &pdfParser{b: st.data, pos: min(st.first+off, len(st.data)), budget: c.fin.budget, strict: true}
				if _, err := sp.value(0); err != nil {
					return err
				}
			}
			c.infra[stm] = true
		}
	}
	slices.SortFunc(spans, func(a, b [2]int) int { return a[0] - b[0] })
	cur := c.end
	for _, sp := range spans {
		if sp[0] < cur || !allGapSpace(c.fin.b[cur:sp[0]]) {
			return errNotSignatureOnly
		}
		cur = sp[1]
	}
	if !allGapSpace(c.fin.b[cur:]) {
		return errNotSignatureOnly
	}
	return nil
}

func trailerCompatible(base, later pdfDict, infoOmitted bool) bool {
	// /Info: суурийнхтай яг ижил заалт (суурьт байсан бол орхихгүй, байгаагүй бол нэмэхгүй); infoOmitted
	// нь дуудагчийн зөвшөөрсөн ганц үл хамаарах тохиолдол.
	if !infoOmitted && !pdfEqual(later["Info"], base["Info"]) {
		return false
	}
	if bid, ok := base["ID"].(pdfArr); ok && len(bid) == 2 {
		if lid, has := later["ID"]; has {
			if a, ok := lid.(pdfArr); !ok || len(a) != 2 || !pdfEqual(a[0], bid[0]) {
				return false
			}
		}
	}
	bs, _ := base["Size"].(int64)
	ls, ok := later["Size"].(int64)
	return ok && ls >= bs
}

// diff — суурь ба эцсийн xref-ийг харьцуулж changed/isNew-г бөглөнө.
func (c *classifier) diff() error {
	for num, be := range c.base.xref {
		if !be.inUse() {
			continue
		}
		// Суурийн xref мужийн гадна руу заасан бол тэр байрлалыг хожим бөглөж болно.
		if be.kind == entUse && be.off >= c.end {
			return errNotSignatureOnly
		}
		// Чөлөөлөгдсөн / алга болсон объект = нуух халдлага.
		if !c.fin.xref[num].inUse() {
			return errNotSignatureOnly
		}
	}
	for num, fe := range c.fin.xref {
		if !fe.inUse() {
			continue
		}
		be := c.base.xref[num]
		if !be.inUse() {
			c.isNew[num], c.changed[num] = true, true
			continue
		}
		if be == fe && (be.kind == entUse || c.base.xref[be.off] == c.fin.xref[fe.off]) {
			continue // ижил байт
		}
		bo, err := c.base.get(num)
		if err != nil {
			return err
		}
		fo, err := c.fin.get(num)
		if err != nil {
			return err
		}
		// Хэлбэр (шууд ↔ ObjStm доторх) эсвэл үеийн дугаар солигдсон бол утга ижил ч татгалзана: үе
		// солигдвол хуучин заалтууд «сул» болно, манай signer хэзээ ч ингэдэггүй.
		// Ганц үл хамаарах (own, APPEARANCE_SPEC.md §5): ObjStm доторх хуучин хуудас / /Annots массивыг PAdES бичигч
		// шууд объектоор (ижил дугаар, үе 0) дахин бичнэ — ref-үүд хүчинтэй хэвээр; үүргийг run() (ownRewrite: өөрчлөгдсөн,
		// зөвшөөрөгдсөн page/annots) шалгана. Хуримтлагдсан (strict биш) own-profile шалгалтад алхам бүр аль хэдийн own
		// горимоор шалгагдсан. Шууд → ObjStm, үе солих — үргэлж татгалзана.
		unpack := be.kind == entComp && fe.kind == entUse && fe.gen == 0 && (c.own || !c.strict && c.ownProfile && !c.dssOnly)
		if (be.kind != fe.kind || be.gen != fe.gen) && !unpack {
			return errNotSignatureOnly
		}
		if unpack && pdfEqual(bo, fo) {
			return errNotSignatureOnly // ижил утгаар дахин бичихгүй
		}
		if !pdfEqual(bo, fo) {
			c.changed[num] = true
		}
	}
	return nil
}

// container — эцсийн талын утга fv-г задална; owner нь түүнийг агуулж буй объект, role нь энэ байрлалын
// үүрэг. fv нь ref бол заасан объект нь шинэ, эсвэл суурьт ЯГ энэ байрлалд байсан (bv == fv) объект байх
// ёстой — хуучин объектыг (өөрчлөгдсөн ч, өөрчлөгдөөгүй ч) суурьт гүйцэтгээгүй үүрэгт ашиглахыг хориглоно.
func (c *classifier) container(bv, fv any, owner int, role string) (any, int, error) {
	r, ok := fv.(pdfRef)
	if !ok {
		return fv, owner, nil
	}
	if !c.isNew[r.num] && bv != fv {
		return nil, 0, errNotSignatureOnly
	}
	if err := c.claim(r.num, role); err != nil {
		return nil, 0, err
	}
	val, err := c.fin.deref(r)
	if err != nil {
		return nil, 0, err
	}
	c.edges[[2]int{owner, r.num}]++
	if c.changed[r.num] {
		c.allowed[r.num] = true
	}
	return val, r.num, nil
}

// baseDict / baseArr — суурийн талын утга (ref бол задална); байхгүй бол nil.
func (c *classifier) baseDict(v any) (pdfDict, error) {
	o, err := c.base.resolve(v)
	if err != nil || o == nil {
		return nil, err
	}
	d, ok := o.(pdfDict)
	if !ok {
		return nil, errNotSignatureOnly
	}
	return d, nil
}

func (c *classifier) baseArr(v any) (pdfArr, error) {
	o, err := c.base.resolve(v)
	if err != nil || o == nil {
		return nil, err
	}
	a, ok := o.(pdfArr)
	if !ok {
		return nil, errNotSignatureOnly
	}
	return a, nil
}

// sameExcept — хоёр толийн keys-ээс бусад түлхүүр бүтцээрээ ижил эсэх.
func sameExcept(a, b pdfDict, keys ...string) bool {
	for _, d := range []pdfDict{a, b} {
		for k := range d {
			if !slices.Contains(keys, k) && !pdfEqual(a[k], b[k]) {
				return false
			}
		}
	}
	return true
}

func onlyKeys(d pdfDict, keys ...string) bool {
	for k := range d {
		if !slices.Contains(keys, k) {
			return false
		}
	}
	return true
}

func (c *classifier) catalog() error {
	fr, ok1 := c.fin.trailer["Root"].(pdfRef)
	br, ok2 := c.base.trailer["Root"].(pdfRef)
	if !ok1 || !ok2 || fr.num != br.num && !c.isNew[fr.num] {
		return errNotSignatureOnly
	}
	fo, err := c.fin.deref(fr)
	if err != nil {
		return err
	}
	bo, err := c.base.deref(br)
	if err != nil {
		return err
	}
	fc, ok1 := fo.(pdfDict)
	bc, ok2 := bo.(pdfDict)
	// /Extensions-ийг манай signer хэзээ ч өөрчилдөггүй тул аливаа өөрчлөлтийг нь зөвшөөрөхгүй.
	except := []string{"AcroForm", "DSS", "Perms", "Version"}
	if c.dssOnly {
		except = append(except, "Extensions", "Metadata")
	}
	if !ok1 || !ok2 || !sameExcept(bc, fc, except...) {
		return errNotSignatureOnly
	}
	if c.own {
		// /DSS, /Perms хөндөгдөхгүй; /Version: digitorus зөвхөн толгой 1.5-аас доош бөгөөд суурийн Catalog-т
		// /Version байхгүй үед /1.5 нэмдэг.
		if !sameExcept(bc, fc, "AcroForm", "Version") || !pdfEqual(bc["Version"], fc["Version"]) && (bc["Version"] != nil || fc["Version"] != pdfName("1.5")) {
			return errNotSignatureOnly
		}
	}
	c.root, c.allowed[fr.num] = fr.num, true
	if err := c.claim(fr.num, "catalog"); err != nil {
		return err
	}
	if err := c.pageTree(fc["Pages"]); err != nil {
		return err
	}
	if !pdfEqual(bc["Version"], fc["Version"]) {
		// /Version зөвхөн ӨСӨЖ болно («M.m» хэлбэртэй нэр, толгойн болон суурийн Catalog-ийн хувилбараас
		// багагүй): бууруулбал viewer шинэ боломжийг (xref stream, ObjStm …) өөрөөр тайлбарлаж болно.
		// digitorus/pdfsign 1.5-аас доош толгойтой баримтад /Version /1.5 нэмдэг.
		name, _ := fc["Version"].(pdfName)
		nv, ok := pdfVersion(string(name))
		floor, ok2 := pdfVersion(string(c.base.b[min(len(c.base.b), 5):min(len(c.base.b), 8)]))
		if bn, has := bc["Version"]; has {
			s, _ := bn.(pdfName)
			bv, ok3 := pdfVersion(string(s))
			ok2, floor = ok2 && ok3, max(floor, bv)
		}
		if !ok || !ok2 || !bytes.HasPrefix(c.base.b, []byte("%PDF-")) || nv < floor {
			return errNotSignatureOnly
		}
		if c.dssOnly {
			c.infoWork = true
		} else {
			c.sigWork = true
		}
	}
	if c.dssOnly {
		if err := c.extensions(bc["Extensions"], fc["Extensions"]); err != nil {
			return err
		}
		if err := c.metadata(bc["Metadata"], fc["Metadata"]); err != nil {
			return err
		}
	}
	if err := c.acroForm(bc["AcroForm"], fc["AcroForm"]); err != nil {
		return err
	}
	if !pdfEqual(bc["Perms"], fc["Perms"]) {
		// /Perms: зөвхөн гарын үсгийн толь руу заана (DocMDP, UR).
		c.sigWork = true
		bpd, err := c.baseDict(bc["Perms"])
		if err != nil {
			return err
		}
		pv, pn, err := c.container(bc["Perms"], fc["Perms"], c.root, "perms")
		if err != nil {
			return err
		}
		pd, ok := pv.(pdfDict)
		if !ok || !onlyKeys(pd, "DocMDP", "UR", "UR3") {
			return errNotSignatureOnly
		}
		for _, key := range slices.Sorted(maps.Keys(pd)) {
			// Мөр бүр: энэ алхамд шинээр ангилагдсан гарын үсгийн толь, эсвэл суурийн /Perms-д ЯГ энэ
			// түлхүүрээр байсан, өөрчлөгдөөгүй объект. Хуучин, Sig биш объектыг шинээр зааж болохгүй.
			r, ok := pd[key].(pdfRef)
			if !ok || !c.sigDicts[r.num] && (c.changed[r.num] || bpd[key] != pd[key]) {
				return errNotSignatureOnly
			}
			c.edges[[2]int{pn, r.num}]++
		}
	}
	return c.dss(bc["DSS"], fc["DSS"])
}

// pageTree — эцсийн Catalog-ийн /Pages-ээс /Kids-ээр дамжин хүрэх /Type /Page объектуудыг c.pages-д цуглуулна.
// Мод нь суурийнхтай ижил (Catalog-ийн /Pages болон /Pages зангилаа өөрчлөгдвөл өөр газар баригдана).
func (c *classifier) pageTree(root any) error {
	stack := []any{root}
	visited := map[int]bool{}
	for len(stack) > 0 {
		r, ok := stack[len(stack)-1].(pdfRef)
		stack = stack[:len(stack)-1]
		if !ok || visited[r.num] {
			return errNotSignatureOnly
		}
		visited[r.num] = true
		o, err := c.fin.deref(r)
		if err != nil {
			return err
		}
		d, _ := o.(pdfDict)
		switch d["Type"] {
		case pdfName("Page"):
			c.pages[r.num] = true
		case pdfName("Pages"):
			kids, err := c.fin.resolve(d["Kids"])
			if err != nil {
				return err
			}
			arr, ok := kids.(pdfArr)
			if !ok {
				return errNotSignatureOnly
			}
			stack = append(stack, arr...)
		default:
			return errNotSignatureOnly
		}
	}
	return nil
}

// page — хуудас p: өөрөө эсвэл шууд бус /Annots массив нь өөрчлөгдсөн бол цорын ганц ялгаа нь /Annots-ийн
// төгсгөлд шинэ гарын үсгийн widget нэмэгдсэн байх ёстой. Шууд бус массив нь суурьт ЯГ энэ хуудасны
// /Annots байсан, өөр хаанаас ч заагдаагүй байна.
func (c *classifier) page(p int) error {
	fo, err := c.fin.get(p)
	if err != nil {
		return err
	}
	fd, ok := fo.(pdfDict)
	if !ok || c.isNew[p] {
		return errNotSignatureOnly
	}
	bd := fd
	if c.changed[p] {
		bo, err := c.base.get(p)
		if err != nil {
			return err
		}
		// /Type нь /Annots биш тул sameExcept суурьт ч /Type /Page байсныг баталгаажуулна.
		if bd, ok = bo.(pdfDict); !ok || !sameExcept(bd, fd, "Annots") {
			return errNotSignatureOnly
		}
		if err := c.claim(p, "page"); err != nil {
			return err
		}
		c.sigWork, c.allowed[p] = true, true
	}
	ar, indirect := fd["Annots"].(pdfRef)
	if !c.changed[p] && !(indirect && c.changed[ar.num]) {
		return nil
	}
	if fd["Annots"] == nil {
		if bd["Annots"] != nil {
			return errNotSignatureOnly
		}
		return nil
	}
	ba, err := c.baseArr(bd["Annots"])
	if err != nil {
		return err
	}
	v, anum, err := c.container(bd["Annots"], fd["Annots"], p, "annots")
	if err != nil {
		return err
	}
	fa, ok := v.(pdfArr)
	if !ok {
		return errNotSignatureOnly
	}
	if anum != p {
		if _, shared := c.annotsOf[anum]; shared {
			return errNotSignatureOnly
		}
		c.annotsOf[anum] = p
		if c.changed[anum] {
			c.sigWork, c.exclusive[anum] = true, true
		}
	}
	if len(fa) < len(ba) {
		return errNotSignatureOnly
	}
	for i, e := range fa {
		if i < len(ba) {
			if !pdfEqual(ba[i], e) {
				return errNotSignatureOnly
			}
			continue
		}
		// Нэмэгдсэн мөр: энэ алхамд ангилагдсан шинэ гарын үсгийн widget, аль ч /Annots-д ганц удаа.
		r, ok := e.(pdfRef)
		if _, placed := c.widgetPage[r.num]; !ok || !c.widgets[r.num] || placed {
			return errNotSignatureOnly
		}
		c.widgetPage[r.num] = p
		c.edges[[2]int{anum, r.num}]++
	}
	return nil
}

// pdfVersion — «M.m» (1.0 … 2.9) → M*10+m.
func pdfVersion(s string) (int, bool) {
	if len(s) != 3 || s[1] != '.' || s[0] != '1' && s[0] != '2' || s[2] < '0' || s[2] > '9' {
		return 0, false
	}
	return int(s[0]-'0')*10 + int(s[2]-'0'), true
}

func (c *classifier) acroForm(bv, fv any) error {
	if fv == nil {
		if bv != nil {
			return errNotSignatureOnly
		}
		return nil
	}
	bd, err := c.baseDict(bv)
	if err != nil {
		return err
	}
	v, num, err := c.container(bv, fv, c.root, "acroform")
	if err != nil {
		return err
	}
	fd, ok := v.(pdfDict)
	// /DA, /DR зэрэг бусад түлхүүр хэвээр байх ёстой: шинэ AcroForm-д зөвхөн /Fields, /SigFlags.
	if !ok || !sameExcept(bd, fd, "Fields", "SigFlags") {
		return errNotSignatureOnly
	}
	// /SigFlags: хэвээр, эсвэл 1 (SignaturesExist) / 3 (+AppendOnly) болж ӨСНӨ; хасагдахгүй, буурахгүй —
	// AppendOnly-г унтраавал viewer баримтыг бүтнээр дахин хадгалахыг (гарын үсгийг эвдэхийг) зөвшөөрнө.
	if !pdfEqual(bd["SigFlags"], fd["SigFlags"]) {
		nf, ok := fd["SigFlags"].(int64)
		of, was := bd["SigFlags"].(int64)
		if !ok || nf != 1 && nf != 3 || bd["SigFlags"] != nil && !was || nf < of {
			return errNotSignatureOnly
		}
	}
	if !pdfEqual(bd["SigFlags"], fd["SigFlags"]) || bd == nil {
		c.sigWork = true
	}
	if c.own {
		// digitorus: Catalog дотор шууд «/AcroForm << /Fields [өмнөх талбарууд + шинэ] /SigFlags 3 >>».
		_, direct := fv.(pdfDict)
		_, fieldsDirect := fd["Fields"].(pdfArr)
		// Бусад түлхүүр (/DA /DR …) байвал суурийнхтай яг ижил (дээрх sameExcept) — PAdES бичигч хадгалдаг.
		if !direct || !fieldsDirect || fd["SigFlags"] != int64(3) {
			return errNotSignatureOnly
		}
	}
	bf, err := c.baseArr(bd["Fields"])
	if err != nil {
		return err
	}
	if c.own {
		// Суурийн талбаруудын нэр (/T): шинэ талбарын нэр эдгээртэй давхцаж болохгүй (newField).
		for _, e := range bf {
			o, err := c.base.resolve(e)
			if err != nil {
				return err
			}
			field, ok := o.(pdfDict)
			if _, isRef := e.(pdfRef); !ok || !isRef {
				return errNotSignatureOnly
			}
			if t, ok := field["T"].(pdfStr); ok {
				c.fieldNames[pdfTextString(t)] = true
			}
		}
	}
	v, fnum, err := c.container(bd["Fields"], fd["Fields"], num, "fields")
	if err != nil {
		return err
	}
	ff, ok := v.(pdfArr)
	if v != nil && !ok || len(ff) < len(bf) {
		return errNotSignatureOnly
	}
	for i, e := range ff {
		r, isRef := e.(pdfRef)
		switch {
		case i < len(bf):
			// Суурийн талбарууд дарааллаараа хэвээр; өөрчлөгдсөн нь зөвхөн бөглөгдсөн хоосон талбар.
			if !pdfEqual(bf[i], e) {
				return errNotSignatureOnly
			}
			if isRef && c.changed[r.num] {
				if c.own { // бөглөгдсөн хуучин талбар: манай signer үргэлж шинэ талбар нэмдэг
					return errNotSignatureOnly
				}
				if err := c.filledField(r.num); err != nil {
					return err
				}
			}
		case !isRef:
			return errNotSignatureOnly
		default:
			if err := c.newField(r, fnum); err != nil {
				return err
			}
		}
	}
	return nil
}

// newField — /Fields-д нэмэгдсэн шинэ гарын үсгийн талбар (талбар + widget нэг объект).
func (c *classifier) newField(r pdfRef, owner int) error {
	if !c.isNew[r.num] || c.widgets[r.num] {
		return errNotSignatureOnly
	}
	o, err := c.fin.deref(r)
	if err != nil {
		return err
	}
	d, ok := o.(pdfDict)
	if !ok || !onlyKeys(d, sigFieldKeys...) || d["FT"] != pdfName("Sig") {
		return errNotSignatureOnly
	}
	if t, has := d["Type"]; has && t != pdfName("Annot") {
		return errNotSignatureOnly
	}
	if t, has := d["Subtype"]; has && t != pdfName("Widget") {
		return errNotSignatureOnly
	}
	for _, k := range []string{"T", "TU", "M"} {
		if v, has := d[k]; has {
			if _, ok := v.(pdfStr); !ok {
				return errNotSignatureOnly
			}
		}
	}
	for _, k := range []string{"F", "Ff"} {
		if v, has := d[k]; has {
			if _, ok := v.(int64); !ok {
				return errNotSignatureOnly
			}
		}
	}
	if c.own {
		// digitorus-ийн үл харагдах widget: /Type /Annot /Subtype /Widget /Rect [0 0 0 0] (/P хуудас) /F 132
		// (Print|Locked) /FT /Sig /T /V. /AP болон өөр түлхүүр байхгүй. Эсвэл PAdES бичигчийн харагдах widget
		// (APPEARANCE_SPEC.md): widget + /AP-ийн 11 объект яг дахин үүсгэсэнтэй тэнцүү (ownVisible).
		if _, vis := d["AP"]; vis {
			if err := c.ownVisible(d, r.num); err != nil {
				return err
			}
			c.ownVis[r.num] = true
		} else if !onlyKeys(d, ownFieldKeys...) || d["Type"] != pdfName("Annot") || d["Subtype"] != pdfName("Widget") ||
			!pdfEqual(d["Rect"], pdfArr{int64(0), int64(0), int64(0), int64(0)}) || d["F"] != int64(132) {
			return errNotSignatureOnly
		}
		// /T: digitorus «Signature N» (N = өмнөх гарын үсгийн тоо + 1) гэж ASCII-аар бичдэг. Суурийн талбарын
		// болон энэ ангилалд аль хэдийн үзсэн шинэ талбарын нэртэй давхцахгүй.
		name, ok := ownText(d["T"], 32)
		if !ok || !ownFieldName(name) || d["T"] != pdfStr(name) || c.fieldNames[name] {
			return errNotSignatureOnly
		}
		c.fieldNames[name] = true
	}
	c.widgetP[r.num] = 0
	if p, has := d["P"]; has {
		pr, ok := p.(pdfRef)
		if !ok {
			return errNotSignatureOnly
		}
		c.widgetP[r.num] = pr.num // хуудас мөн эсэхийг run() шалгана
	}
	if err := c.claim(r.num, "field"); err != nil {
		return err
	}
	c.sigWork = true
	c.widgets[r.num], c.allowed[r.num] = true, true
	c.edges[[2]int{owner, r.num}]++
	if err := c.sigValue(d["V"], r.num); err != nil {
		return err
	}
	return c.appearance(nil, d, r.num)
}

// filledField — суурьт байсан хоосон гарын үсгийн талбар бөглөгдсөн.
func (c *classifier) filledField(num int) error {
	bo, err := c.base.get(num)
	if err != nil {
		return err
	}
	fo, err := c.fin.get(num)
	if err != nil {
		return err
	}
	bd, ok1 := bo.(pdfDict)
	fd, ok2 := fo.(pdfDict)
	if !ok1 || !ok2 || bd["FT"] != pdfName("Sig") || bd["V"] != nil || bd["Kids"] != nil || !sameExcept(bd, fd, "V", "AP", "M") {
		return errNotSignatureOnly
	}
	// Суурийн объект нь үнэхээр гарын үсгийн widget байх ёстой: өөр төрлийн annotation (Stamp, FreeText …)
	// эсвэл өөр үүрэгтэй объектод /FT /Sig наасан бол /V, /AP нэмэх нь түүний харагдацыг өөрчилнө.
	if t, has := bd["Type"]; has && t != pdfName("Annot") {
		return errNotSignatureOnly
	}
	if t, has := bd["Subtype"]; has && t != pdfName("Widget") {
		return errNotSignatureOnly
	}
	if m, has := fd["M"]; has {
		if _, ok := m.(pdfStr); !ok {
			return errNotSignatureOnly
		}
	}
	if err := c.claim(num, "field"); err != nil {
		return err
	}
	c.sigWork = true
	c.allowed[num] = true
	if err := c.sigValue(fd["V"], num); err != nil {
		return err
	}
	return c.appearance(bd, fd, num)
}

// sigValue — талбарын /V: шинэ гарын үсгийн толь.
func (c *classifier) sigValue(v any, owner int) error {
	r, ok := v.(pdfRef)
	// Нэг Sig толийг хоёр талбар хуваалцахгүй.
	if !ok || !c.isNew[r.num] || c.sigDicts[r.num] {
		return errNotSignatureOnly
	}
	if err := c.claim(r.num, "sig"); err != nil {
		return err
	}
	o, err := c.fin.deref(r)
	if err != nil {
		return err
	}
	d, ok := o.(pdfDict)
	if !ok || !onlyKeys(d, sigDictKeys...) {
		return errNotSignatureOnly
	}
	if c.own && (!onlyKeys(d, ownSigDictKeys...) || d["Type"] != pdfName("Sig")) {
		return errNotSignatureOnly
	}
	if c.own {
		// PAdES хэлбэр (internal/pdfsign/pades, §4.1): /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached,
		// /ByteRange /Contents /M (+ /Name, байгууллагын нэрийн өмнөөс бол /Reason) л — ownText-ээр доор шалгана.
		if d["SubFilter"] == pdfName("ETSI.CAdES.detached") &&
			(!onlyKeys(d, padesSigDictKeys...) || d["Filter"] != pdfName("Adobe.PPKLite") || d["M"] == nil) {
			return errNotSignatureOnly
		}
		// Чөлөөт бичвэрүүд: digitorus-ийн бичдэг хэлбэр (ownText), /M нь яг «D:YYYYMMDDHHmmSS±HH'mm'».
		for _, k := range []string{"Name", "Location", "Reason", "ContactInfo", "M"} {
			v, has := d[k]
			if !has {
				continue
			}
			if text, ok := ownText(v, ownTextLimit); !ok || k == "M" && !ownDate(text) {
				return errNotSignatureOnly
			}
		}
	}
	// /Type /DocTimeStamp-ийг Extract задалдаггүй (шалгадаггүй) тул гарын үсэгт тооцохгүй — татгалзана.
	if t, has := d["Type"]; has && t != pdfName("Sig") {
		return errNotSignatureOnly
	}
	br, ok := d["ByteRange"].(pdfArr)
	if _, isStr := d["Contents"].(pdfStr); !ok || !isStr || len(br) != 4 {
		return errNotSignatureOnly
	}
	// ByteRange = [0 a b c]: бүхэл тоо, 0 < a < b, c ≥ 0, энэ алхмын суурийн төгсгөлөөс цааш хамарсан.
	var n [4]int64
	for i, x := range br {
		if n[i], ok = x.(int64); !ok {
			return errNotSignatureOnly
		}
	}
	if n[0] != 0 || n[1] <= 0 || n[2] <= n[1] || n[3] < 0 || n[2]+n[3] <= int64(c.end) {
		return errNotSignatureOnly
	}
	// Энэ толь нь Extract-ийн задалж, криптографаар шалгасан гарын үсгүүдийн нэг байх ёстой (ижил объект,
	// ижил ByteRange). Extract нь [a, b) завсар ЯГ энэ толийн /Contents-ийн <hex> мөн эсэхийг шалгасан
	// (signedBytes) тул тэр шалгалт энд давтагдахгүй.
	if !slices.Equal(c.known[r.num], n[:]) {
		return errNotSignatureOnly
	}
	// Sig толь дотор шууд бус заалт байж болохгүй. Ганц үл хамаарах зүйл: /Reference-ийн мөрийн
	// /Data → Catalog (суурийн эсвэл эцсийн). Бусад бүх утга шууд байна.
	bad := false
	for k, v := range d {
		if k != "Reference" {
			pdfRefs(v, func(pdfRef) { bad = true })
			continue
		}
		rows, ok := v.(pdfArr)
		bad = bad || !ok
		for _, row := range rows {
			rd, ok := row.(pdfDict)
			if !ok || !onlyKeys(rd, "Type", "TransformMethod", "TransformParams", "DigestMethod", "Data") {
				bad = true
				continue
			}
			for rk, rv := range rd {
				data, isRef := rv.(pdfRef)
				switch {
				case rk != "Data":
					pdfRefs(rv, func(pdfRef) { bad = true })
				case isRef && data.num == c.root:
					c.edges[[2]int{r.num, c.root}]++
				case isRef && data == c.base.trailer["Root"]:
				default:
					bad = true
				}
			}
		}
	}
	if bad {
		return errNotSignatureOnly
	}
	c.sigDicts[r.num], c.allowed[r.num] = true, true
	c.edges[[2]int{owner, r.num}]++
	return nil
}

// appearance — widget-ийн /Rect ба /AP. Харагдах гарын үсгийг зөвшөөрнө, гэхдээ дүрслэлийн объект бүр
// шинэ бөгөөд зөвхөн дүрслэл дотроосоо заагдсан байх ёстой (run()-ийн edges шалгалт).
func (c *classifier) appearance(base, d pdfDict, widget int) error {
	if rect, has := d["Rect"]; has {
		a, ok := rect.(pdfArr)
		if !ok || len(a) != 4 {
			return errNotSignatureOnly
		}
		var f [4]float64
		for i, x := range a {
			switch n := x.(type) {
			case int64:
				f[i] = float64(n)
			case float64:
				f[i] = n
			default:
				return errNotSignatureOnly
			}
		}
		if f[0] != f[2] && f[1] != f[3] {
			c.visible = true
		}
	}
	ap, has := d["AP"]
	if !has {
		return nil
	}
	c.visible = true
	if pdfEqual(base["AP"], ap) {
		return nil // суурийн (гарын үсэгт хамрагдсан) дүрслэл хэвээр
	}
	apd, ok := ap.(pdfDict)
	if !ok || !onlyKeys(apd, "N", "R", "D") {
		return errNotSignatureOnly
	}
	var queue []int
	for _, key := range slices.Sorted(maps.Keys(apd)) {
		// Шинэ дүрслэлийн XObject нь шинэ stream байх ёстой: хуучин объектыг (жишээ нь хуудасны агуулгын
		// stream) суурьт гүйцэтгээгүй үүрэгт ашиглахгүй.
		r, ok := apd[key].(pdfRef)
		if !ok || !c.isNew[r.num] {
			return errNotSignatureOnly
		}
		if o, err := c.fin.deref(r); err != nil {
			return err
		} else if _, ok := o.(pdfStream); !ok {
			return errNotSignatureOnly
		}
		c.edges[[2]int{widget, r.num}]++
		queue = append(queue, r.num)
	}
	for len(queue) > 0 {
		n := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if !c.changed[n] {
			continue // суурийн өөрчлөгдөөгүй объектыг (жишээ нь фонт) нөөц болгон дахин ашиглаж болно
		}
		// Дүрслэлийн объект: шинэ, өөр үүрэггүй (DSS stream, Sig толь, widget, /Annots, xref/ObjStm биш).
		if !c.isNew[n] || c.infra[n] {
			return errNotSignatureOnly
		}
		if err := c.claim(n, "ap"); err != nil {
			return err
		}
		if c.seen[n] {
			continue
		}
		c.seen[n], c.allowed[n] = true, true
		o, err := c.fin.get(n)
		if err != nil {
			return err
		}
		pdfRefs(o, func(t pdfRef) {
			c.edges[[2]int{n, t.num}]++
			queue = append(queue, t.num)
		})
	}
	return nil
}

// dssNode — DSS-ийн сав (толь/массив). Өөрчлөгдсөн бол онцгой: зөвхөн DSS дотроос заагдана.
func (c *classifier) dssNode(bv, fv any, owner int, role string) (any, int, error) {
	v, num, err := c.container(bv, fv, owner, role)
	if err == nil && num != owner && c.changed[num] {
		c.exclusive[num] = true
		c.ltvWork = true
	}
	return v, num, err
}

// baseLTVStreams — суурийн DSS/VRI-д LTV stream-ийн үүрэгтэй байсан объектууд. Хуучин объектыг шинэ
// массив/VRI мөрөөс зөвхөн эдгээрээс л зааж болно (VRI мөр /Certs-д байгаа сертификатыг дахин заах нь хэвийн).
func (c *classifier) baseLTVStreams(bd pdfDict) (map[int]bool, error) {
	out := map[int]bool{}
	add := func(d pdfDict, keys ...string) error {
		for _, k := range keys {
			a, err := c.baseArr(d[k])
			if err != nil {
				return err
			}
			for _, e := range a {
				if r, ok := e.(pdfRef); ok {
					out[r.num] = true
				}
			}
		}
		return nil
	}
	if err := add(bd, "Certs", "OCSPs", "CRLs"); err != nil {
		return nil, err
	}
	vri, err := c.baseDict(bd["VRI"])
	if err != nil {
		return nil, err
	}
	for _, e := range vri {
		ed, err := c.baseDict(e)
		if err != nil {
			return nil, err
		}
		if err := add(ed, "Cert", "OCSP", "CRL"); err != nil {
			return nil, err
		}
		if r, ok := ed["TS"].(pdfRef); ok {
			out[r.num] = true
		}
	}
	return out, nil
}

func (c *classifier) dss(bv, fv any) error {
	if fv == nil {
		if bv != nil {
			return errNotSignatureOnly
		}
		return nil
	}
	bd, err := c.baseDict(bv)
	if err != nil {
		return err
	}
	old, err := c.baseLTVStreams(bd)
	if err != nil {
		return err
	}
	v, num, err := c.dssNode(bv, fv, c.root, "dss")
	if err != nil {
		return err
	}
	fd, ok := v.(pdfDict)
	if !ok || !onlyKeys(fd, "Type", "VRI", "Certs", "OCSPs", "CRLs") {
		return errNotSignatureOnly
	}
	for _, k := range []string{"Certs", "OCSPs", "CRLs"} {
		if err := c.ltvArray(bd[k], fd[k], num, old); err != nil {
			return err
		}
	}
	if fd["VRI"] == nil {
		return nil
	}
	bvri, err := c.baseDict(bd["VRI"])
	if err != nil {
		return err
	}
	v, vnum, err := c.dssNode(bd["VRI"], fd["VRI"], num, "vri")
	if err != nil {
		return err
	}
	fvri, ok := v.(pdfDict)
	if !ok {
		return errNotSignatureOnly
	}
	for _, key := range slices.Sorted(maps.Keys(fvri)) {
		bed, err := c.baseDict(bvri[key])
		if err != nil {
			return err
		}
		v, enum, err := c.dssNode(bvri[key], fvri[key], vnum, "vrient")
		if err != nil {
			return err
		}
		fed, ok := v.(pdfDict)
		if !ok || !onlyKeys(fed, "Type", "Cert", "OCSP", "CRL", "TU", "TS") {
			return errNotSignatureOnly
		}
		for _, k := range []string{"Cert", "OCSP", "CRL"} {
			if err := c.ltvArray(bed[k], fed[k], enum, old); err != nil {
				return err
			}
		}
		if _, ok := fed["TU"].(pdfStr); fed["TU"] != nil && !ok {
			return errNotSignatureOnly
		}
		if ts, has := fed["TS"]; has {
			if err := c.ltvStream(ts, enum, old); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *classifier) ltvArray(bv, fv any, owner int, old map[int]bool) error {
	if fv == nil {
		return nil
	}
	v, num, err := c.dssNode(bv, fv, owner, "ltvarr")
	if err != nil {
		return err
	}
	a, ok := v.(pdfArr)
	if !ok {
		return errNotSignatureOnly
	}
	if num != owner { // шууд бус массивыг /Certs ба VRI хоёулаа зааж болно (ижил үүрэг): элементийг нэг л удаа тоолно
		if c.seen[num] {
			return nil
		}
		c.seen[num] = true
	}
	for _, e := range a {
		if err := c.ltvStream(e, num, old); err != nil {
			return err
		}
	}
	return nil
}

// ltvStream — сертификат/OCSP/CRL/цагийн тэмдгийн stream: суурийн DSS-д аль хэдийн LTV stream байсан
// өөрчлөгдөөгүй объект (old), эсвэл шинэ, ref-гүй тольтой stream.
func (c *classifier) ltvStream(v any, owner int, old map[int]bool) error {
	r, ok := v.(pdfRef)
	if !ok {
		return errNotSignatureOnly
	}
	if err := c.claim(r.num, "ltv"); err != nil {
		return err
	}
	c.edges[[2]int{owner, r.num}]++
	if !c.isNew[r.num] {
		if c.changed[r.num] || !old[r.num] {
			return errNotSignatureOnly
		}
		return nil
	}
	o, err := c.fin.deref(r)
	if err != nil {
		return err
	}
	s, ok := o.(pdfStream)
	// /Type-гүй (EmbeddedFile, XObject, Metadata … гэж өөрийгөө зарлаагүй) шинэ stream.
	if !ok || !onlyKeys(s.dict, "Length", "Filter", "DecodeParms") {
		return errNotSignatureOnly
	}
	pdfRefs(s.dict, func(pdfRef) { ok = false })
	if !ok {
		return errNotSignatureOnly
	}
	c.allowed[r.num] = true
	c.ltvWork = true
	return nil
}

// ltvRoles — DSS-only алхамд өөрчлөгдөж/шинээр гарч болох объектын үүрэг.
var ltvRoles = []string{"catalog", "dss", "vri", "vrient", "ltvarr", "ltv", "info", "metadata"}

// dssOnlyRules — гарын үсэггүй алхам: шинэ гарын үсэг, талбар, харагдах зүйл, гарын үсгийн бусад ажил
// (AcroForm, /Perms, хуудас) байхгүй; өөрчлөгдсөн/шинэ объект бүр LTV эсвэл мэдээллийн үүрэгтэй; /Version
// /Extensions /Info /Metadata-ийн өөрчлөлт зөвхөн DSS-ийг бодитоор өөрчилсөн алхамд.
func (c *classifier) dssOnlyRules() error {
	if len(c.sigDicts) > 0 || len(c.widgets) > 0 || c.sigWork || c.visible || (c.infoWork || c.ownProfile) && !c.ltvWork {
		return errNotSignatureOnly
	}
	for n := range c.changed {
		if c.infra[n] || !c.strict && !c.allowed[n] {
			continue
		}
		if !slices.Contains(ltvRoles, c.role[n]) {
			return errNotSignatureOnly
		}
	}
	for n := range c.rewritten {
		if !c.changed[n] || !c.allowed[n] || !slices.Contains(ltvRoles, c.role[n]) {
			return errNotSignatureOnly
		}
	}
	return nil
}

// extensions — Catalog /Extensions (ISO 32000-2 §7.12): DSS-only алхамд шууд толь, утга бүр шууд толь
// (эсвэл ийм тольны массив) — /BaseVersion (нэр), /ExtensionLevel (бүхэл), /ExtensionRevision /URL
// (бичвэр) л; ямар ч заалтгүй (агуулга руу хүрэх зам үгүй).
func (c *classifier) extensions(bv, fv any) error {
	if pdfEqual(bv, fv) {
		return nil
	}
	d, ok := fv.(pdfDict)
	if !ok {
		return errNotSignatureOnly
	}
	dev := func(x any) bool {
		e, ok := x.(pdfDict)
		if !ok || !onlyKeys(e, "Type", "BaseVersion", "ExtensionLevel", "ExtensionRevision", "URL") {
			return false
		}
		if _, ok := e["BaseVersion"].(pdfName); !ok {
			return false
		}
		if _, ok := e["ExtensionLevel"].(int64); !ok {
			return false
		}
		for _, k := range []string{"ExtensionRevision", "URL"} {
			if v, has := e[k]; has {
				if _, ok := v.(pdfStr); !ok {
					return false
				}
			}
		}
		if t, has := e["Type"]; has && t != pdfName("DeveloperExtensions") {
			return false
		}
		return true
	}
	for k, v := range d {
		if k == "Type" {
			if v != pdfName("Extensions") {
				return errNotSignatureOnly
			}
			continue
		}
		if arr, isArr := v.(pdfArr); isArr {
			for _, e := range arr {
				if !dev(e) {
					return errNotSignatureOnly
				}
			}
		} else if !dev(v) {
			return errNotSignatureOnly
		}
	}
	c.infoWork = true
	return nil
}

// metadata — Catalog /Metadata (XMP): DSS-only алхамд шинэ эсвэл ижил байрлалд дахин бичсэн stream —
// /Type /Metadata /Subtype /XML, тольд заалтгүй. Харагдах агуулгад нөлөөлөхгүй.
func (c *classifier) metadata(bv, fv any) error {
	r, ok := fv.(pdfRef)
	if pdfEqual(bv, fv) && (!ok || !c.changed[r.num]) {
		return nil
	}
	if !ok {
		return errNotSignatureOnly
	}
	v, num, err := c.container(bv, fv, c.root, "metadata")
	if err != nil {
		return err
	}
	st, ok := v.(pdfStream)
	if !ok || !onlyKeys(st.dict, "Type", "Subtype", "Length", "Filter", "DecodeParms") ||
		st.dict["Type"] != pdfName("Metadata") || st.dict["Subtype"] != pdfName("XML") {
		return errNotSignatureOnly
	}
	bad := false
	pdfRefs(st.dict, func(pdfRef) { bad = true })
	if bad {
		return errNotSignatureOnly
	}
	if c.isNew[num] {
		c.exclusive[num] = true
	}
	c.infoWork = true
	return nil
}

// info — trailer /Info: DSS-only алхамд суурийн ИЖИЛ объект дахин бичигдэж болно (ModDate, Producer …):
// шууд бичвэр/нэр утгатай толь, заалтгүй. /Info заалт өөрөө trailerCompatible-аар хэвээр.
func (c *classifier) info() error {
	r, ok := c.fin.trailer["Info"].(pdfRef)
	if !ok || !c.changed[r.num] || c.isNew[r.num] {
		return nil
	}
	fo, err := c.fin.get(r.num)
	if err != nil {
		return err
	}
	d, ok := fo.(pdfDict)
	if !ok {
		return errNotSignatureOnly
	}
	for _, v := range d {
		switch v.(type) {
		case pdfStr, pdfName:
		default:
			return errNotSignatureOnly
		}
	}
	if err := c.claim(r.num, "info"); err != nil {
		return err
	}
	c.allowed[r.num], c.infoWork = true, true
	return nil
}
