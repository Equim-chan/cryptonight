// +build !amd64

package aes

func cnExpandKey(key []uint64, rkeys *[40]uint32) {
	cnExpandKeyGo(key, rkeys)
}

func cnRounds(dst, src []uint64, rkeys *[40]uint32) {
	cnRoundsGo(dst, src, rkeys)
}

func cnSingleRound(dst, src []uint64, rkey *[4]uint32) {
	cnSingleRoundGo(dst, src, rkey)
}
