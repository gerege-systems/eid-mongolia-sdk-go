package eid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ── RP-ийн санаачилсан тамганы эрхийн хүсэлт (CA V156): POST /seal/grants → 202, GET /seal/grants/{id} ──

const sealGrantID = "0b7d2c9e-41f6-4a3d-8e52-7c1a9f0e6d24"

// caSealGrantRequest — CA handlers_seal_grant_rp.go-ийн req (JSON tag-ууд ЯГ ижил; CA DisallowUnknownFields).
type caSealGrantRequest struct {
	OrgEtsi   string `json:"orgEtsi"`
	SessionID string `json:"sessionId"`
}

// sealGrantBody — CA dto.RPSealGrantStatus; extra нь `,"key":…` хэлбэрийн нэмэлт талбарууд.
func sealGrantBody(status, extra string) string {
	return `{"grantId":"` + sealGrantID + `","orgEtsi":"NTRMN-6235972","status":"` + status +
		`","expiresAt":"2026-11-20T05:07:00Z"` + extra + `}`
}

func TestSealGrant_Request(t *testing.T) {
	c, rc := server(t, func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var req caSealGrantRequest
		if err := dec.Decode(&req); err != nil || req.OrgEtsi != "NTRMN-6235972" || req.SessionID != "sess-1" {
			w.WriteHeader(400)
			_, _ = fmt.Fprint(w, `{"error":"JSON буруу","code":"REQUEST_INVALID"}`)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprint(w, sealGrantBody("PENDING", ""))
	})
	g, err := c.Seal.RequestGrant(context.Background(), " NTRMN-6235972 ", "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if g.GrantID != sealGrantID || g.Status != SealGrantPending || g.OrgEtsi != "NTRMN-6235972" || g.ExpiresAt.IsZero() || g.ApprovedAt != nil {
		t.Fatalf("%+v", g)
	}
	req, _ := rc.last()
	if req.Method != http.MethodPost || req.URL.Path != "/seal/grants" || req.Header.Get("Authorization") != "Bearer "+creds.APISecret {
		t.Fatal(req.Method, req.URL.Path)
	}
	// Хоосон оролт — сүлжээнд гарахгүй.
	for _, in := range [][2]string{{"", "sess-1"}, {"NTRMN-6235972", " "}} {
		var ve *ValidationError
		if _, err := c.Seal.RequestGrant(context.Background(), in[0], in[1]); !errors.As(err, &ve) {
			t.Fatal(in, err)
		}
	}
	if _, err := c.Seal.GrantStatus(context.Background(), ""); err == nil {
		t.Fatal("хоосон grantID")
	}
	if rc.count() != 1 {
		t.Fatalf("хүсэлт %d", rc.count())
	}
}

func TestSealGrant_StatusApproved(t *testing.T) {
	c, rc := server(t, jsonReply(200, sealGrantBody("APPROVED", `,"approvedAt":"2026-11-20T05:01:00Z"`)))
	g, err := c.Seal.GrantStatus(context.Background(), sealGrantID)
	if err != nil || g.Status != SealGrantApproved || g.ApprovedAt == nil || g.ApprovedAt.Minute() != 1 {
		t.Fatal(err, g)
	}
	req, _ := rc.last()
	if req.Method != http.MethodGet || req.URL.Path != "/seal/grants/"+sealGrantID {
		t.Fatal(req.Method, req.URL.Path)
	}
	// grantId/status-гүй хариу — ValidationError.
	c, _ = server(t, jsonReply(200, `{"orgEtsi":"NTRMN-6235972"}`))
	var ve *ValidationError
	if _, err := c.Seal.GrantStatus(context.Background(), sealGrantID); !errors.As(err, &ve) {
		t.Fatal(err)
	}
}

func TestSealGrant_ErrorCodes(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		status   int
		code     string
		sentinel error
	}{
		{400, CodeRequestInvalid, ErrRequestInvalid},
		{403, CodeRPNotRegistered, ErrRPNotRegistered},
		{403, CodeNotOrgCEO, ErrNotOrgCEO},
		{404, CodeAuthSessionNotFound, ErrAuthSessionNotFound},
		{404, CodeOrgNotFound, ErrOrgNotFound},
		{409, CodeAuthSessionWrongFlow, ErrAuthSessionWrongFlow},
		{409, CodeAuthSessionNotCompleted, ErrAuthSessionNotCompleted},
		{409, CodeAuthSessionTooOld, ErrAuthSessionTooOld},
		{409, CodeAuthSessionAlreadyUsed, ErrAuthSessionAlreadyUsed},
		{409, CodeOrgNotActive, ErrOrgNotActive},
		{409, CodeRPNotActive, ErrRPNotActive},
		{409, CodeSealGrantAlreadyApproved, ErrSealGrantAlreadyApproved},
		{409, CodeRPPermissionsFull, ErrRPPermissionsFull},
		{409, CodeSealApproverUnavailable, ErrSealApproverUnavailable},
	} {
		c, _ := server(t, jsonReply(tc.status, `{"error":"x","code":"`+tc.code+`"}`))
		_, err := c.Seal.RequestGrant(ctx, "NTRMN-6235972", "sess-1")
		if !errors.Is(err, tc.sentinel) {
			t.Fatalf("%s: %v", tc.code, err)
		}
		if tc.status == 403 {
			var fe *ForbiddenError
			if !errors.As(err, &fe) || fe.Code != tc.code {
				t.Fatalf("%s: %T", tc.code, err)
			}
		} else {
			var ae *APIError
			if !errors.As(err, &ae) || ae.Status != tc.status || ae.Code != tc.code || ae.Retryable() {
				t.Fatalf("%s: %v", tc.code, err)
			}
		}
		// Өөр sentinel таарахгүй.
		if (tc.sentinel != ErrNotOrgCEO && errors.Is(err, ErrNotOrgCEO)) || (tc.sentinel != ErrAuthSessionTooOld && errors.Is(err, ErrAuthSessionTooOld)) {
			t.Fatalf("%s: илүү sentinel таарав", tc.code)
		}
	}
	// 429 RATE_LIMITED + Retry-After.
	c, _ := server(t, sealSeq(sealStep{status: 429, body: `{"error":"хэт олон","code":"RATE_LIMITED"}`, header: map[string]string{"Retry-After": "3600"}}))
	var ae *APIError
	if _, err := c.Seal.RequestGrant(ctx, "NTRMN-6235972", "sess-1"); !errors.As(err, &ae) || ae.Status != 429 || !ae.Retryable() || ae.RetryAfter != time.Hour {
		t.Fatal(err)
	}
	// GrantStatus 404 SEAL_GRANT_NOT_FOUND.
	c, _ = server(t, jsonReply(404, `{"error":"олдсонгүй","code":"SEAL_GRANT_NOT_FOUND"}`))
	if _, err := c.Seal.GrantStatus(ctx, sealGrantID); !errors.Is(err, ErrSealGrantNotFound) || errors.Is(err, ErrSealRequestNotFound) {
		t.Fatal(err)
	}
}

func TestSealGrant_Wait(t *testing.T) {
	c, rc := server(t, sealSeq(
		sealStep{status: 200, body: sealGrantBody("PENDING", "")},
		sealStep{status: 429, body: `{"error":"хэт олон","code":"RATE_LIMITED"}`, header: map[string]string{"Retry-After": "1"}},
		sealStep{status: 200, body: sealGrantBody("APPROVED", `,"approvedAt":"2026-11-20T05:01:00Z"`)},
	))
	t0 := time.Now()
	g, err := c.Seal.WaitForGrant(context.Background(), sealGrantID, &SealWaitOptions{Interval: time.Millisecond})
	if err != nil || g.Status != SealGrantApproved {
		t.Fatal(err, g)
	}
	if rc.count() != 3 || time.Since(t0) < 950*time.Millisecond {
		t.Fatalf("poll %d, %v", rc.count(), time.Since(t0))
	}
}

func TestSealGrant_WaitTerminal(t *testing.T) {
	for _, tc := range []struct {
		status  SealGrantStatus
		extra   string
		failure string
	}{
		{SealGrantRejected, "", ""},
		{SealGrantExpired, `,"failure":"EXPIRED"`, "EXPIRED"},
		{SealGrantFailed, `,"failure":"PUSH_FAILED"`, "PUSH_FAILED"},
		{SealGrantRevoked, `,"approvedAt":"2026-11-20T05:01:00Z","revokedAt":"2026-11-20T06:00:00Z","failure":"CANCELLED"`, "CANCELLED"},
	} {
		c, rc := server(t, sealSeq(sealStep{status: 200, body: sealGrantBody("PENDING", "")}, sealStep{status: 200, body: sealGrantBody(string(tc.status), tc.extra)}))
		_, err := c.Seal.WaitForGrant(context.Background(), sealGrantID, &SealWaitOptions{Interval: time.Millisecond})
		var ge *SealGrantError
		if !errors.As(err, &ge) || ge.Outcome != tc.status || ge.GrantID != sealGrantID || ge.Failure != tc.failure {
			t.Fatalf("%s: %v", tc.status, err)
		}
		if rc.count() != 2 {
			t.Fatalf("%s: poll %d", tc.status, rc.count())
		}
	}
	// Timeout — PENDING хэвээр; ctx цуцлалт; 404 шууд.
	c, _ := server(t, jsonReply(200, sealGrantBody("PENDING", "")))
	_, err := c.Seal.WaitForGrant(context.Background(), sealGrantID, &SealWaitOptions{Interval: 5 * time.Millisecond, Timeout: 30 * time.Millisecond})
	var ge *SealGrantError
	if !errors.As(err, &ge) || ge.Outcome != SealGrantTimeout {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Seal.WaitForGrant(ctx, sealGrantID, &SealWaitOptions{Interval: 10 * time.Second}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	c, rc := server(t, jsonReply(404, `{"error":"олдсонгүй","code":"SEAL_GRANT_NOT_FOUND"}`))
	if _, err := c.Seal.WaitForGrant(context.Background(), sealGrantID, &SealWaitOptions{Interval: time.Millisecond}); !errors.Is(err, ErrSealGrantNotFound) || rc.count() != 1 {
		t.Fatal(err)
	}
}

func TestOrganization_SealGrants(t *testing.T) {
	body := `{"personEtsi":"PNOMN-12345678","organizations":[{"orgEtsi":"NTRMN-6235972","orgName":"Гэрэгэ Системс ХХК","orgStatus":"ACTIVE","grants":[` +
		`{"grantId":"g1","rpName":"eidmongolia.mn","rpDomain":"eidmongolia.mn","status":"APPROVED","createdAt":"2026-11-20T05:00:00Z",` +
		`"decidedAt":"2026-11-20T05:01:00Z","approverName":"Бат","sealCount":12,"sealCount30d":3,"lastSealedAt":"2026-11-20T07:00:00Z"},` +
		`{"grantId":"g2","rpName":"Банк","status":"PENDING","createdAt":"2026-11-20T05:00:00Z","expiresAt":"2026-11-20T05:07:00Z",` +
		`"sealCount":0,"sealCount30d":0,"lastSealedAt":null},` +
		`{"grantId":"g3","rpName":"Даатгал","status":"APPROVED","createdAt":"2026-11-20T05:00:00Z"}]},` +
		`{"orgEtsi":"NTRMN-1","orgName":"Б","orgStatus":"SUSPENDED","grants":null}],"future":1}`
	c, rc := server(t, jsonReply(200, body))
	r, err := c.Organization.SealGrants(context.Background(), "PNOMN-12345678")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := rc.last()
	if req.Method != http.MethodGet || req.URL.Path != "/organization/seal-grants/etsi/PNOMN-12345678" {
		t.Fatal(req.Method, req.URL.Path)
	}
	if r.PersonEtsi != "PNOMN-12345678" || len(r.Organizations) != 2 || len(r.Raw) == 0 {
		t.Fatalf("%+v", r)
	}
	o := r.Organizations[0]
	if o.OrgName != "Гэрэгэ Системс ХХК" || o.OrgStatus != "ACTIVE" || len(o.Grants) != 3 {
		t.Fatalf("%+v", o)
	}
	g1, g2, g3 := o.Grants[0], o.Grants[1], o.Grants[2]
	if g1.Status != SealGrantApproved || g1.RPDomain != "eidmongolia.mn" || g1.ApproverName != "Бат" || g1.DecidedAt == nil ||
		g1.SealCount == nil || *g1.SealCount != 12 || *g1.SealCount30d != 3 || g1.LastSealedAt == nil {
		t.Fatalf("g1 %+v", g1)
	}
	if g2.Status != SealGrantPending || g2.ExpiresAt == nil || g2.SealCount == nil || *g2.SealCount != 0 || g2.LastSealedAt != nil {
		t.Fatalf("g2 %+v", g2)
	}
	// Статистик боломжгүй — талбаргүй → nil (0 биш).
	if g3.SealCount != nil || g3.SealCount30d != nil || g3.LastSealedAt != nil {
		t.Fatalf("g3 %+v", g3)
	}
	if r.Organizations[1].Grants == nil || len(r.Organizations[1].Grants) != 0 {
		t.Fatal("nil grants → []")
	}
	// Хоосон хариу / 403 (PKI_READ эсвэл 24 цагийн нэвтрэлт алга).
	c, _ = server(t, jsonReply(200, `{"personEtsi":"PNOMN-12345678","organizations":null}`))
	if r, err := c.Organization.SealGrants(context.Background(), "PNOMN-12345678"); err != nil || r.Organizations == nil || len(r.Organizations) != 0 {
		t.Fatal(err, r)
	}
	c, _ = server(t, jsonReply(403, `{"error":"PKI_READ эрхгүй","code":"PERMISSION_DENIED"}`))
	var fe *ForbiddenError
	if _, err := c.Organization.SealGrants(context.Background(), "PNOMN-12345678"); !errors.As(err, &fe) {
		t.Fatal(err)
	}
}
