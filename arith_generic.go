// +build !amd64

package cryptonight

func byteAddMul(ret *[2]uint64, x, y uint64) {
	xhi, yhi := x>>32, y>>32
	xlo, ylo := x&0xffffffff, y&0xffffffff

	hihi := xhi * yhi
	lolo := xlo * ylo
	lohi := xlo * yhi
	hilo := xhi * ylo

	mid := lolo>>32 + lohi&0xffffffff + hilo&0xffffffff
	ret[0] += mid<<32 | (lolo & 0xffffffff)
	ret[1] += hihi + lohi>>32 + hilo>>32 + mid>>32
}

func mul128(low, high *uint64, x, y uint64) {
	aLow := x & 0xffffffff
	aHigh := x >> 32
	bLow := y & 0xffffffff
	bHigh := y >> 32

	res := aLow * bLow
	lowRes1 := res & 0xffffffff
	carry := res >> 32

	res = aHigh*bLow + carry
	highResHigh1 := res >> 32
	highResLow1 := res & 0xffffffff

	res = aLow * bHigh
	lowRes2 := res & 0xffffffff
	carry = res >> 32

	res = aHigh*bHigh + carry
	highResHigh2 := res >> 32
	highResLow2 := res & 0xffffffff

	r := highResLow1 + lowRes2
	carry = r >> 32
	*low = (r << 32) | lowRes1
	r = highResHigh1 + highResLow2 + carry
	d3 := r & 0xffffffff
	carry = r >> 32
	r = highResHigh2 + carry
	*high = d3 | (r << 32)
}
