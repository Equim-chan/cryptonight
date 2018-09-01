// +build !amd64

package cryptonight

func mul128(x, y uint64) (lo, hi uint64) {
	xhi, yhi := x>>32, y>>32
	xlo, ylo := x&0xffffffff, y&0xffffffff

	hihi := xhi * yhi
	lolo := xlo * ylo
	lohi := xlo * yhi
	hilo := xhi * ylo

	mid := lolo>>32 + lohi&0xffffffff + hilo&0xffffffff
	lo = mid<<32 | (lolo & 0xffffffff)
	hi = hihi + lohi>>32 + hilo>>32 + mid>>32

	return
}
