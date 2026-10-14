package core

import (
	"os"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// TestMain — тестийн pdfcpu туслахууд (xrefStreamPDF г.м.) config.yml уншиж/бичихгүй (js/wasm-д FS алга).
func TestMain(m *testing.M) {
	model.ConfigPath = "disable"
	os.Exit(m.Run())
}
