package cryptonight

//go:noescape
func byteAddMul(ret *[2]uint64, x, y uint64)

//go:noescape
func mul128(low, high *uint64, x, y uint64)
