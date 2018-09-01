package cryptonight

//go:noescape
func mul128(x, y uint64) (lo, hi uint64)
