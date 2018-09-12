package aes

//go:noescape
func CnExpandKeyAsm(src *uint64, rkey *[40]uint32)

//go:noescape
func CnRoundsAsm(dst, src *uint64, rkeys *[40]uint32)
