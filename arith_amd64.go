package cryptonight

//go:noescape
func byteMul(product *[2]uint64, x, y uint64)
