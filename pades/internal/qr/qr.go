// Package qr — PAGE_SPEC.md §QR: ISO/IEC 18004 QR code, byte mode, ECC M, хувилбар 1–6 (хамгийн бага багтах), маск
// ТОГТМОЛ 0 ((row+col) mod 2 == 0). Penalty-ээр маск сонгохгүй — хэл бүрд ижил матриц гарахын тулд.
package qr

import "errors"

// ErrTooLong — өгөгдөл 6-M хувилбарт (106 байт) багтахгүй.
var ErrTooLong = errors.New("qr: өгөгдөл хэт урт (≤ 106 байт)")

// Mask — тогтмол маск (PAGE_SPEC.md).
const Mask = 0

type version struct {
	ecPerBlock, blocks, dataPerBlock int
	align                            []int
}

// ECC M, хувилбар 1–6 (ISO/IEC 18004 Table 9, Annex E).
var versions = [7]version{
	{},
	{10, 1, 16, nil},
	{16, 1, 28, []int{6, 18}},
	{26, 1, 44, []int{6, 22}},
	{18, 2, 32, []int{6, 26}},
	{24, 2, 43, []int{6, 30}},
	{16, 4, 27, []int{6, 34}},
}

// Encode — data-г QR матриц болгоно: [row][col], true = хар модуль. Quiet zone ОРОХГҮЙ.
func Encode(data []byte) ([][]bool, error) {
	ver := 0
	for v := 1; v <= 6; v++ {
		capBits := versions[v].blocks * versions[v].dataPerBlock * 8
		if 4+8+8*len(data) <= capBits {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, ErrTooLong
	}
	vi := versions[ver]
	total := vi.blocks * vi.dataPerBlock
	// ── өгөгдлийн бит: mode 0100, тоо 8 бит, байт, terminator ≤ 4, 8-д дүүргэх, pad 0xEC 0x11 ──
	var bits []bool
	put := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, v>>i&1 == 1)
		}
	}
	put(0b0100, 4)
	put(len(data), 8)
	for _, b := range data {
		put(int(b), 8)
	}
	put(0, min(4, total*8-len(bits)))
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	cw := make([]byte, 0, total)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			if bits[i+j] {
				b |= 1 << (7 - j)
			}
		}
		cw = append(cw, b)
	}
	for i := 0; len(cw) < total; i++ {
		cw = append(cw, [2]byte{0xEC, 0x11}[i%2])
	}
	// ── блок + Reed–Solomon, interleave ──
	gen := rsGenerator(vi.ecPerBlock)
	dataBlocks := make([][]byte, vi.blocks)
	ecBlocks := make([][]byte, vi.blocks)
	for b := range vi.blocks {
		dataBlocks[b] = cw[b*vi.dataPerBlock : (b+1)*vi.dataPerBlock]
		ecBlocks[b] = rsRemainder(dataBlocks[b], gen)
	}
	var final []byte
	for i := range vi.dataPerBlock {
		for b := range vi.blocks {
			final = append(final, dataBlocks[b][i])
		}
	}
	for i := range vi.ecPerBlock {
		for b := range vi.blocks {
			final = append(final, ecBlocks[b][i])
		}
	}
	return place(ver, vi, final), nil
}

func place(ver int, vi version, final []byte) [][]bool {
	n := 17 + 4*ver
	m := make([][]bool, n)
	fn := make([][]bool, n) // функциональ модуль (өгөгдөл бичихгүй)
	for i := range n {
		m[i], fn[i] = make([]bool, n), make([]bool, n)
	}
	set := func(r, c int, dark bool) { m[r][c], fn[r][c] = dark, true }
	finder := func(r0, c0 int) {
		for r := -1; r <= 7; r++ {
			for c := -1; c <= 7; c++ {
				rr, cc := r0+r, c0+c
				if rr < 0 || cc < 0 || rr >= n || cc >= n {
					continue
				}
				dark := r >= 0 && r <= 6 && c >= 0 && c <= 6 &&
					(r == 0 || r == 6 || c == 0 || c == 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4))
				set(rr, cc, dark)
			}
		}
	}
	finder(0, 0)
	finder(0, n-7)
	finder(n-7, 0)
	for i := 8; i < n-8; i++ { // timing
		set(6, i, i%2 == 0)
		set(i, 6, i%2 == 0)
	}
	for _, r := range vi.align {
		for _, c := range vi.align {
			if r < 9 && c < 9 || r < 9 && c > n-9 || r > n-9 && c < 9 { // finder-тэй давхцах 3 байрлал
				continue
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					set(r+dr, c+dc, max(abs(dr), abs(dc)) != 1)
				}
			}
		}
	}
	// Формат мэдээлэл (ECC M = 00, маск 3 бит) → BCH(15,5), XOR 0x5412; бит i (0 = LSB).
	f := formatBits(0b00<<3 | Mask)
	fb := func(i int) bool { return f>>i&1 == 1 }
	for i := 0; i <= 5; i++ {
		set(i, 8, fb(i))
	}
	set(7, 8, fb(6))
	set(8, 8, fb(7))
	set(8, 7, fb(8))
	for i := 9; i < 15; i++ {
		set(8, 14-i, fb(i))
	}
	for i := 0; i < 8; i++ {
		set(8, n-1-i, fb(i))
	}
	for i := 8; i < 15; i++ {
		set(n-15+i, 8, fb(i))
	}
	set(n-8, 8, true) // dark module
	// Өгөгдөл: баруун доод буланаас 2 баганаар зигзаг, 6-р баганыг алгасна.
	bit := 0
	up := true
	for col := n - 1; col > 0; col -= 2 {
		if col == 6 {
			col--
		}
		for k := range n {
			r := k
			if up {
				r = n - 1 - k
			}
			for _, c := range []int{col, col - 1} {
				if fn[r][c] {
					continue
				}
				dark := false
				if bit < len(final)*8 {
					dark = final[bit/8]>>(7-bit%8)&1 == 1
				}
				bit++
				if (r+c)%2 == 0 { // маск 0
					dark = !dark
				}
				m[r][c] = dark
			}
		}
		up = !up
	}
	return m
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func formatBits(data int) int {
	g := 0x537
	v := data << 10
	for i := 14; i >= 10; i-- {
		if v>>i&1 == 1 {
			v ^= g << (i - 10)
		}
	}
	return (data<<10 | v) ^ 0x5412
}

// ── GF(256), primitive 0x11D ──

var gfExp, gfLog = func() ([512]byte, [256]byte) {
	var e [512]byte
	var l [256]byte
	x := 1
	for i := range 255 {
		e[i] = byte(x)
		l[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		e[i] = e[i-255]
	}
	return e, l
}()

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// rsGenerator — ∏(x − α^i), i = 0..n-1; коэффициент өндөр зэргээс (тэргүүлэх 1-ийг оруулахгүй).
func rsGenerator(n int) []byte {
	g := []byte{1}
	for i := range n {
		next := make([]byte, len(g)+1)
		for j, c := range g {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		g = next
	}
	return g[1:]
}

func rsRemainder(data, gen []byte) []byte {
	rem := make([]byte, len(gen))
	for _, d := range data {
		f := d ^ rem[0]
		copy(rem, rem[1:])
		rem[len(rem)-1] = 0
		for i, g := range gen {
			rem[i] ^= gfMul(g, f)
		}
	}
	return rem
}
