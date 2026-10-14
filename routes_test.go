package eid

import "testing"

func TestRouteExpand(t *testing.T) {
	if got := routePDFDocument.expand("a/b c"); got != "/pdf/sign/a%2Fb%20c/document" {
		t.Fatalf("expand = %q", got)
	}
	for _, r := range rpRoutes {
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
