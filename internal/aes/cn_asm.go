// +build amd64

package aes

func cnExpandKey(key []byte, rkeys []uint32) {
	if !supportsAES {
		expandKeyGo(key, rkeys, nil)
	} else {
		cnExpandKeyAsm(&key[0], &rkeys[0])
	}
}

func cnRounds(dst, src []byte, rkeys []uint32) {
	if !supportsAES {
		cnRoundsGo(dst, src, rkeys)
	} else {
		cnRoundsAsm(&dst[0], &src[0], &rkeys[0])
	}
}

func cnSingleRound(dst, src []byte, rkey []uint32) {
	if !supportsAES {
		cnSingleRoundGo(dst, src, rkey)
	} else {
		cnSingleRoundAsm(&dst[0], &src[0], &rkey[0])
	}
}

//go:noescape
func cnRoundsAsm(dst, src *byte, rkeys *uint32)

//go:noescape
func cnSingleRoundAsm(dst, src *byte, rkey *uint32)

//go:noescape
func cnExpandKeyAsm(src *byte, rkey *uint32)
