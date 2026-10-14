//go:build contract

// Гэрээний тест — сүлжээ шаарддаг тул энгийн `go test`-д орохгүй: `go test -tags contract ./...`.
// SDK-ийн хүлээдэг OIDC утгууд live login.eidmongolia.mn discovery-тэй таарах ёстой.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestContractOIDCDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, Issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery: HTTP %d", resp.StatusCode)
	}
	var d struct {
		Issuer                 string   `json:"issuer"`
		AuthorizationEndpoint  string   `json:"authorization_endpoint"`
		TokenEndpoint          string   `json:"token_endpoint"`
		JWKSURI                string   `json:"jwks_uri"`
		IDTokenAlgs            []string `json:"id_token_signing_alg_values_supported"`
		CodeChallengeMethods   []string `json:"code_challenge_methods_supported"`
		TokenEndpointAuth      []string `json:"token_endpoint_auth_methods_supported"`
		ScopesSupported        []string `json:"scopes_supported"`
		ACRValuesSupported     []string `json:"acr_values_supported"`
		ClaimsSupported        []string `json:"claims_supported"`
		ResponseTypesSupported []string `json:"response_types_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("discovery JSON: %v", err)
	}

	if d.Issuer != Issuer {
		t.Errorf("issuer = %q, SDK Issuer = %q", d.Issuer, Issuer)
	}
	for name, u := range map[string]string{"authorization_endpoint": d.AuthorizationEndpoint, "token_endpoint": d.TokenEndpoint, "jwks_uri": d.JWKSURI} {
		if !strings.HasPrefix(u, "https://") {
			t.Errorf("%s = %q (https:// хүлээсэн)", name, u)
		}
	}
	has := func(field string, list []string, want string) {
		if !slices.Contains(list, want) {
			t.Errorf("%s %v-д SDK-ийн %q алга", field, list, want)
		}
	}
	has("id_token_signing_alg_values_supported", d.IDTokenAlgs, idTokenAlg)
	has("code_challenge_methods_supported", d.CodeChallengeMethods, pkceMethod)
	has("token_endpoint_auth_methods_supported", d.TokenEndpointAuth, tokenEndpointAuthMethod)
	has("response_types_supported", d.ResponseTypesSupported, "code")
	has("scopes_supported", d.ScopesSupported, defaultScope)
	has("acr_values_supported", d.ACRValuesSupported, ACRQualified)
	has("acr_values_supported", d.ACRValuesSupported, ACRAdvanced)

	// Claims-ийн талбар бүр (json tag) claims_supported-д: заавал талбар алга бол fail, omitempty бол WARN.
	var optionalMissing []string
	ct := reflect.TypeOf(Claims{})
	for i := 0; i < ct.NumField(); i++ {
		name, opts, _ := strings.Cut(ct.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" || slices.Contains(d.ClaimsSupported, name) {
			continue
		}
		if strings.Contains(opts, "omitempty") {
			optionalMissing = append(optionalMissing, name)
		} else {
			t.Errorf("claims_supported %v-д SDK Claims.%s (%q) алга", d.ClaimsSupported, ct.Field(i).Name, name)
		}
	}
	for _, n := range optionalMissing {
		fmt.Fprintf(os.Stderr, "WARN: claims_supported-д SDK-ийн optional claim алга: %s\n", n)
	}
	if len(optionalMissing) > 0 && os.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Printf("::warning title=claims_supported-д SDK-ийн optional claim алга::%s\n", strings.Join(optionalMissing, ", "))
	}
}
