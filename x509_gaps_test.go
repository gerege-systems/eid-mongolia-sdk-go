package eid

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestResponseSizeLimits(t *testing.T) {
	ctx := context.Background()
	// JSON > 4 MiB → *ResponseTooLargeError (таслаж задлахгүй).
	big := `{"personEtsi":"PNOMN-1","pad":"` + strings.Repeat("a", maxJSONBody) + `"}`
	c, _ := server(t, jsonReply(200, big))
	_, err := c.Organization.GetRepresentations(ctx, "PNOMN-1")
	var tl *ResponseTooLargeError
	if !errors.As(err, &tl) || tl.Limit != maxJSONBody || strings.Contains(tl.Error(), "PNOMN-1") {
		t.Fatalf("ResponseTooLargeError хүлээв: %v", err)
	}
	// Яг хязгаар хүртэл — зөвшөөрнө.
	exact := `{"personEtsi":"PNOMN-1","pad":"` + strings.Repeat("a", maxJSONBody-len(`{"personEtsi":"PNOMN-1","pad":""}`)) + `"}`
	c, _ = server(t, jsonReply(200, exact))
	if _, err := c.Organization.GetRepresentations(ctx, "PNOMN-1"); err != nil {
		t.Fatal(err)
	}

}

func TestRepresentationsRaw(t *testing.T) {
	c, _ := server(t, jsonReply(200, `{"personEtsi":"PNOMN-1","representations":[{"orgEtsi":"NTRMN-1"}],"future":{"x":1}}`))
	r, err := c.Organization.GetRepresentations(context.Background(), "PNOMN-1")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(r.Raw, &m); err != nil || string(m["future"]) != `{"x":1}` || len(r.Representations) != 1 {
		t.Fatalf("Raw: %s %v", r.Raw, err)
	}
}
