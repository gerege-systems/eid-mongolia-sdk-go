package core

import (
	"errors"
	"testing"
)

func TestNum100(t *testing.T) {
	for v, want := range map[int]string{0: "0", 100: "1", 150: "1.5", 105: "1.05", 59528: "595.28", -50: "-0.5", -1234: "-12.34", 7: "0.07"} {
		if got := Num100(v); got != want {
			t.Errorf("Num100(%d) = %q, хүлээсэн %q", v, got, want)
		}
	}
	if Round100(595.275) != 59528 || Round100(0.004) != 0 || Round100(-0.005) != 0 {
		t.Fatal("Round100")
	}
}

// TestVisibleRect — APPEARANCE_SPEC.md §1: CropBox-ийн эх (llx, lly ≠ 0) ба /Rotate 0/90/180/270.
func TestVisibleRect(t *testing.T) {
	box := [4]int{1000, 2000, 61200, 81200} // 602 × 792 pt, эх (10, 20)
	// Харагдах (36, 36) 220 × 64 pt.
	cases := map[int][4]int{
		0:   {4600, 5600, 26600, 12000},   // ux = llx + vx, uy = lly + vy
		90:  {51200, 5600, 57600, 27600},  // ux = urx − vy, uy = lly + vx
		180: {35600, 71200, 57600, 77600}, // ux = urx − vx, uy = ury − vy
		270: {4600, 55600, 11000, 77600},  // ux = llx + vy, uy = ury − vx
	}
	for rot, want := range cases {
		got, err := VisibleRect(box, rot, 3600, 3600, 22000, 6400)
		if err != nil || got != want {
			t.Errorf("rot %d: %v %v, хүлээсэн %v", rot, got, err, want)
		}
	}
	if _, err := VisibleRect(box, 90, 3600, 3600, 80000, 6400); !errors.Is(err, ErrAppearance) {
		t.Errorf("90°-д харагдах өргөн = 792 pt: %v", err)
	}
	if _, err := VisibleRect(box, 0, 59000, 0, 2000, 6400); !errors.Is(err, ErrAppearance) {
		t.Errorf("баруун ирмэгээс гарна: %v", err)
	}
}
