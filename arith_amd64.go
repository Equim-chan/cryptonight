package cryptonight

//go:noescape
func byteAddMul(ret *[2]uint64, x, y uint64)
