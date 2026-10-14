//go:build !(js && wasm)

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNodeSmoke — GOOS=js GOARCH=wasm build-ийг Node-оор ажиллуулж, буруу оролтын дараа runtime амьд, дахин дуудлага
// ажилладгийг шалгана. node байхгүй бол алгасна.
func TestNodeSmoke(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node алга")
	}
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	execJS := filepath.Join(runtime.GOROOT(), "lib", "wasm", "wasm_exec.js")
	if _, err := os.Stat(execJS); err != nil {
		execJS = filepath.Join(runtime.GOROOT(), "misc", "wasm", "wasm_exec.js")
	}
	out := filepath.Join(t.TempDir(), "eidpades.wasm")
	build := exec.Command(goBin, "build", "-o", out, ".") // #nosec G204 -- тест
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("wasm build: %v\n%s", err, b)
	}
	pdf, _ := filepath.Abs(filepath.Join("..", "pades", "testdata", "golden", "input", "quartz-pdf13.pdf"))
	run := exec.Command(node, filepath.Join("testdata", "node_smoke.mjs"), execJS, out, pdf) // #nosec G204 -- тест
	b, err := run.CombinedOutput()
	if err != nil || !strings.Contains(string(b), "OK") {
		t.Fatalf("node: %v\n%s", err, b)
	}
}
