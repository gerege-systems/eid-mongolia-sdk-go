package core

// Stamp placement — PLACEMENT_SPEC.md §6. The requested rect (visible page space, h100) is the first candidate; when it
// collides with the page's occupancy the stamp moves to the first free candidate in a fixed order.

// PlaceStatus — where the stamp ended up and why (Prepared.Placement.Status).
type PlaceStatus string

const (
	// PlaceRequested — the requested rect was free: output is byte-identical to the fixed placement.
	PlaceRequested PlaceStatus = "requested"
	// PlaceMoved — the requested rect overlapped page content; the stamp moved to the first free candidate.
	PlaceMoved PlaceStatus = "moved"
	// PlaceOverlap — no candidate was free; the stamp stays at the requested rect and overlaps content.
	PlaceOverlap PlaceStatus = "overlap"
	// PlaceUnscanned — the page could not be scanned (limit, filter, broken stream); the requested rect is used.
	PlaceUnscanned PlaceStatus = "unscanned"
)

const (
	placePad   = 400  // h100: clearance kept around the stamp
	placeStep  = 1200 // h100: vertical step between candidates
	placeSteps = 100  // at most this many steps up per column
)

// PlaceCandidates — the candidate positions (visible space, h100) in trial order: requested (x, y); mirrored
// (vw − x − w, y); then up the requested column y + k·step (k = 1…, while y + k·step + h ≤ vh − y, k ≤ 100); then up
// the mirrored column. The mirrored column is left out when it equals the requested one.
func PlaceCandidates(vw, vh, x, y, w, h int) [][2]int {
	xl := vw - x - w
	out := [][2]int{{x, y}}
	if xl != x {
		out = append(out, [2]int{xl, y})
	}
	cols := []int{x}
	if xl != x {
		cols = append(cols, xl)
	}
	for _, cx := range cols {
		for k := 1; k <= placeSteps && y+k*placeStep+h <= vh-y; k++ {
			out = append(out, [2]int{cx, y + k*placeStep})
		}
	}
	return out
}

// PlaceVisible — the first candidate whose /Rect, grown by placePad on every side, overlaps no occupied box (strict
// overlap: touching edges are free). ok = false → none is free (the caller keeps the requested rect).
func PlaceVisible(box [4]int, rot, x, y, w, h int, occ [][4]int) (px, py int, ok bool) {
	vw, vh := box[2]-box[0], box[3]-box[1]
	if rot == 90 || rot == 270 {
		vw, vh = vh, vw
	}
	for _, c := range PlaceCandidates(vw, vh, x, y, w, h) {
		r, err := VisibleRect(box, rot, c[0], c[1], w, h)
		if err != nil {
			continue
		}
		e := [4]int{r[0] - placePad, r[1] - placePad, r[2] + placePad, r[3] + placePad}
		free := true
		for _, b := range occ {
			if b[0] < e[2] && e[0] < b[2] && b[1] < e[3] && e[1] < b[3] {
				free = false
				break
			}
		}
		if free {
			return c[0], c[1], true
		}
	}
	return x, y, false
}
