package eid

import "testing"

func TestRouteExpand(t *testing.T) {
	if got := routeSession.expand("a/b c"); got != "/session/a%2Fb%20c" {
		t.Fatalf("expand = %q", got)
	}
	for _, r := range append(append([]rpRoute(nil), rpRoutes...), rpRoutesUndiscovered...) {
		n := 0
		for _, c := range r.path {
			if c == '{' {
				n++
			}
		}
		args := make([]string, n)
		for i := range args {
			args[i] = "x"
		}
		_ = r.expand(args...) // параметрийн тоо зөрвөл panic
	}
}
