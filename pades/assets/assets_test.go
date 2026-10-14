package assets

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

var update = flag.Bool("update", false, "fonts/*.metrics.json-ийг дахин бичих")

// metrics — native SDK-уудад: TTF задлахгүйгээр cmap (Unicode → glyph) ба өргөн (Width1000).
type metrics struct {
	PSName     string      `json:"psName"`
	Length1    int         `json:"length1"`
	UnitsPerEm int         `json:"unitsPerEm"`
	Ascent     int         `json:"ascent"`
	Descent    int         `json:"descent"`
	CapHeight  int         `json:"capHeight"`
	BBox       [4]int      `json:"bbox"`
	Widths     []int       `json:"widths"` // glyph ID → Width1000
	CMap       [][2]uint32 `json:"cmap"`   // [codepoint, glyphID], codepoint-оор эрэмбэлсэн
}

// TestMetricsJSON — fonts/*.metrics.json нь TTF-ээс задалсантай тэнцүү.
func TestMetricsJSON(t *testing.T) {
	for _, get := range []func() (*Font, error){Regular, Bold} {
		f, err := get()
		if err != nil {
			t.Fatal(err)
		}
		m := metrics{PSName: f.PSName, Length1: f.Length1, UnitsPerEm: f.UnitsPerEm, Ascent: f.Ascent, Descent: f.Descent,
			CapHeight: f.CapHeight, BBox: f.BBox}
		for g := range f.Advance {
			m.Widths = append(m.Widths, f.Width1000(uint16(g))) // #nosec G115
		}
		for r, g := range f.GID {
			m.CMap = append(m.CMap, [2]uint32{uint32(r), uint32(g)}) // #nosec G115
		}
		sort.Slice(m.CMap, func(i, j int) bool { return m.CMap[i][0] < m.CMap[j][0] })
		got, _ := json.Marshal(m)
		name := map[string]string{"NotoSans": "NotoSans-Regular", "NotoSans-Bold": "NotoSans-Bold"}[f.PSName]
		path := filepath.Join("fonts", name+".metrics.json")
		if *update {
			if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil { // #nosec G306 -- тест
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path) // #nosec G304 -- тест
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bytes.TrimSpace(want), got) {
			t.Fatal(fmt.Sprintf("%s зөрөв (-update)", path))
		}
	}
}
