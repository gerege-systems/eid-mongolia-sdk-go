package eid

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"time"
)

// PersonService — иргэний PKI самбар (CA docs/EID_PERSON_PKI.md): гэрчилгээ, төхөөрөмж, үйл ажиллагаа, нэгдсэн тоо,
// асран хамгаалж буй хүүхдүүд. RP-д PKI_READ эрх (админ тухайлан олгоно) БА иргэн сүүлийн 24 цагт танай RP-ээр
// амжилттай нэвтэрсэн байх ёстой — эс бөгөөс *ForbiddenError (403); иргэн олдохгүй бол *APIError 404.
// Хариу бүрийн Raw — серверийн түүхий JSON (SDK задлаагүй шинэ талбарт).
type PersonService struct {
	h *httpDoer
}

// PersonCertificate — иргэний нэг гэрчилгээ.
type PersonCertificate struct {
	DocumentNumber string `json:"documentNumber"`
	// Type — AUTH | SIGN | SEAL.
	Type string `json:"type"`
	// KeyMedium — MOBILE | TOKEN | HSM (түлхүүрийн байршил).
	KeyMedium        string `json:"keyMedium"`
	SerialNumber     string `json:"serialNumber"`
	CertificateLevel string `json:"certificateLevel"`
	// Status — VALID | REVOKED | EXPIRED | SUSPENDED.
	Status    string    `json:"status"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	IssuerDN  string    `json:"issuerDn"`
	// IssuedAt — олгосон мөч; хуучин CA-д nil.
	IssuedAt *time.Time `json:"issuedAt,omitempty"`
	// RevokedAt — цуцалсан мөч: REVOKED, мөн сунгалт/дахин бүртгэлээр солигдсон (Status SUSPENDED,
	// RevocationReason "superseded") мөрд (CA !377-оос).
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	// RevocationReason — RFC 5280 CRLReason-ийн нэр (keyCompromise, cACompromise, affiliationChanged, superseded,
	// cessationOfOperation, certificateHold, privilegeWithdrawn г.м.); "" = цуцлаагүй. Status өөрчлөгдөхгүй —
	// солигдсоныг (SUSPENDED) "superseded"-ээр ялга.
	RevocationReason string `json:"revocationReason,omitempty"`
	// CertValue — base64 DER (нийтийн артефакт).
	CertValue string `json:"certValue,omitempty"`
	// Organization — TOKEN мөрөнд токенд холбогдсон байгууллага; хувийн токенд nil.
	Organization *TokenOrganization `json:"organization,omitempty"`
}

// CertCounts — гэрчилгээний статусын тоолол.
type CertCounts struct {
	Valid     int `json:"valid"`
	Revoked   int `json:"revoked"`
	Expired   int `json:"expired"`
	Suspended int `json:"suspended"`
	Total     int `json:"total"`
}

// PersonCertificates — GET /certificates/etsi/{personEtsi}.
type PersonCertificates struct {
	PersonEtsi   string              `json:"personEtsi"`
	Counts       CertCounts          `json:"counts"`
	Certificates []PersonCertificate `json:"certificates"`
	Raw          json.RawMessage     `json:"-"`
}

// PersonDevice — иргэний холбоотой төхөөрөмж.
type PersonDevice struct {
	DeviceID       string `json:"deviceId,omitempty"`
	DocumentNumber string `json:"documentNumber"`
	// Platform — APNS | FCM.
	Platform      string     `json:"platform,omitempty"`
	PushTopic     string     `json:"pushTopic,omitempty"`
	EnrolledAt    time.Time  `json:"enrolledAt"`
	Active        bool       `json:"active"`
	DeactivatedAt *time.Time `json:"deactivatedAt,omitempty"`
}

// PersonDevices — GET /devices/etsi/{personEtsi}.
type PersonDevices struct {
	PersonEtsi  string          `json:"personEtsi"`
	Devices     []PersonDevice  `json:"devices"`
	ActiveCount int             `json:"activeCount"`
	Total       int             `json:"total"`
	Raw         json.RawMessage `json:"-"`
}

// ActivityItem — иргэний үйл ажиллагааны нэг бичлэг (kind/reason-ийн хүснэгт: EID_PERSON_PKI §Activity kind/reason;
// шинэ код нэмэгдэж болно — танихгүйг ерөнхий текстээр харуул).
type ActivityItem struct {
	ID        string `json:"id,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
	// Kind — AUTH | SIGN | PIN_CHECK | ENROLL | TOKEN_AUTH | …
	Kind string `json:"kind"`
	// Flow — AUTHENTICATION | SIGNATURE (зөвхөн AUTH/SIGN).
	Flow string `json:"flow,omitempty"`
	// Outcome — OK | DENIED | FAILED.
	Outcome         string    `json:"outcome"`
	Reason          string    `json:"reason,omitempty"`
	PinSlot         string    `json:"pinSlot,omitempty"`
	EndResult       string    `json:"endResult,omitempty"`
	RPName          string    `json:"rpName,omitempty"`
	SubsystemName   string    `json:"subsystemName,omitempty"`
	DocText         string    `json:"docText,omitempty"`
	InteractionType string    `json:"interactionType,omitempty"`
	DocumentNumber  string    `json:"documentNumber,omitempty"`
	ClientIP        string    `json:"clientIp,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	OnBehalfOfName  string    `json:"onBehalfOfName,omitempty"`
}

// ActivityCounts — flow тус бүрийн session-ий тоо.
type ActivityCounts struct {
	Authentication int `json:"authentication"`
	Signature      int `json:"signature"`
}

// PersonActivity — GET /rp/activity/etsi/{personEtsi} (RP-scoped; eID портал — бүрэн түүх).
type PersonActivity struct {
	PersonEtsi string          `json:"personEtsi"`
	Counts     ActivityCounts  `json:"counts"`
	Sessions   []ActivityItem  `json:"sessions"`
	Total      int             `json:"total"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
	Raw        json.RawMessage `json:"-"`
}

// ActivityQuery — Activity-ийн шүүлт. Тэг утга = серверийн анхдагч (limit 20, offset 0, бүх flow).
type ActivityQuery struct {
	// Flow — "AUTHENTICATION" | "SIGNATURE" | "" (бүгд).
	Flow string
	// Limit — 1–200 (сервер хязгаарлана); 0 = анхдагч.
	Limit int
	// Offset — 0 = эхнээс.
	Offset int
}

// PersonSummary — GET /person/summary/etsi/{personEtsi}: самбарын нэгдсэн тоо. Нэршил Person-тэй ижил (LastName =
// ЭЦГИЙН нэр, FamilyName = УРГИЙН овог).
type PersonSummary struct {
	PersonEtsi          string          `json:"personEtsi"`
	FirstName           string          `json:"firstName,omitempty"`
	LastName            string          `json:"lastName,omitempty"`
	FamilyName          string          `json:"familyName,omitempty"`
	Certificates        CertCounts      `json:"certificates"`
	Activity            ActivityCounts  `json:"activity"`
	DevicesActive       int             `json:"devicesActive"`
	DevicesTotal        int             `json:"devicesTotal"`
	RepresentationCount int             `json:"representationCount"`
	Raw                 json.RawMessage `json:"-"`
}

// PersonChild — асран хамгаалж буй хүүхэд.
type PersonChild struct {
	Etsi  string `json:"etsi"`
	RegNo string `json:"regNo"`
	// Name — «Овог Нэр».
	Name string `json:"name"`
	// BirthDate — YYYY-MM-DD.
	BirthDate string `json:"birthDate,omitempty"`
	// Registered — хүүхэд утсандаа eID бүртгүүлсэн эсэх.
	Registered bool `json:"registered"`
	// CertNotAfter — гэрчилгээний дуусах хугацаа (18 нас); бүртгэлгүй бол nil.
	CertNotAfter *time.Time `json:"certNotAfter,omitempty"`
}

// PersonChildren — GET /person/children/etsi/{personEtsi}.
type PersonChildren struct {
	Children []PersonChild   `json:"children"`
	Raw      json.RawMessage `json:"-"`
}

// Certificates — иргэний бүх гэрчилгээ + статусын тоолол.
func (p *PersonService) Certificates(ctx context.Context, personEtsi string) (*PersonCertificates, error) {
	var r PersonCertificates
	if err := p.get(ctx, routePersonCertificates.expand(personEtsi), &r, &r.Raw); err != nil {
		return nil, err
	}
	return &r, nil
}

// Devices — иргэний холбоотой төхөөрөмжүүд (идэвхтэй + идэвхгүй).
func (p *PersonService) Devices(ctx context.Context, personEtsi string) (*PersonDevices, error) {
	var r PersonDevices
	if err := p.get(ctx, routePersonDevices.expand(personEtsi), &r, &r.Raw); err != nil {
		return nil, err
	}
	return &r, nil
}

// Activity — иргэний үйл ажиллагааны түүх (q nil = анхдагч).
func (p *PersonService) Activity(ctx context.Context, personEtsi string, q *ActivityQuery) (*PersonActivity, error) {
	path := routePersonActivity.expand(personEtsi)
	if q != nil {
		v := url.Values{}
		if q.Flow != "" {
			v.Set("flow", q.Flow)
		}
		if q.Limit > 0 {
			v.Set("limit", strconv.Itoa(q.Limit))
		}
		if q.Offset > 0 {
			v.Set("offset", strconv.Itoa(q.Offset))
		}
		if len(v) > 0 {
			path += "?" + v.Encode()
		}
	}
	var r PersonActivity
	if err := p.get(ctx, path, &r, &r.Raw); err != nil {
		return nil, err
	}
	return &r, nil
}

// Summary — самбарын нэгдсэн тоо (нэг дуудлагаар).
func (p *PersonService) Summary(ctx context.Context, personEtsi string) (*PersonSummary, error) {
	var r PersonSummary
	if err := p.get(ctx, routePersonSummary.expand(personEtsi), &r, &r.Raw); err != nil {
		return nil, err
	}
	return &r, nil
}

// Children — иргэний асран хамгаалж буй хүүхдүүд (зөвхөн унших).
func (p *PersonService) Children(ctx context.Context, personEtsi string) (*PersonChildren, error) {
	var r PersonChildren
	if err := p.get(ctx, routePersonChildren.expand(personEtsi), &r, &r.Raw); err != nil {
		return nil, err
	}
	return &r, nil
}

// get — түүхий хариуг raw-д хадгалж out руу задална.
func (p *PersonService) get(ctx context.Context, path string, out any, raw *json.RawMessage) error {
	if err := p.h.getJSON(ctx, path, 0, raw); err != nil {
		return err
	}
	if len(*raw) == 0 {
		return nil
	}
	return decodeJSON(*raw, path, out)
}
