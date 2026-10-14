package eid

import (
	"context"
	"net/url"
)

// OrganizationService — иргэний төлөөлж чадах (ACTIVE, хугацаа хүчинтэй) байгууллагууд; OnBehalfOf-оос өмнө иргэнд
// сонгуулахад. Иргэн сүүлийн 24 цагт танай RP-ээр нэвтэрсэн байх ёстой (үгүй бол 403).
type OrganizationService struct {
	h *httpDoer
}

// GetRepresentations — GET /organization/representations/etsi/{personEtsi}. Сонголт нь итгэх эх биш — сервер
// session эхлэхэд дахин шалгана.
func (o *OrganizationService) GetRepresentations(ctx context.Context, personEtsi string) (*RepresentationsResponse, error) {
	var r RepresentationsResponse
	if err := o.h.getJSON(ctx, "/organization/representations/etsi/"+url.PathEscape(personEtsi), 0, &r); err != nil {
		return nil, err
	}
	if r.PersonEtsi == "" {
		r.PersonEtsi = personEtsi
	}
	if r.Representations == nil {
		r.Representations = []Representation{}
	}
	return &r, nil
}
