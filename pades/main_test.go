package pades

import (
	"os"
	"testing"
)

// TestMain — js/WASM-д ч тестийн *.pki.test fixture (http) шууд replay хийгдэнэ (allowlist-ийн upgrade-ийг
// TestFetcherJS тусад нь шалгана).
func TestMain(m *testing.M) {
	jsUpgrade = false
	os.Exit(m.Run())
}
