// +build !amd64

package aes

func cnExpandKey(key []byte, rkeys []uint32) {
	expandKeyGo(key, rkeys, nil)
}

func cnRounds(dst, src []byte, rkeys []uint32) {
	cnRoundsGo(dst, src, rkeys)
}

func cnSingleRound(dst, src []byte, rkey []uint32) {
	cnSingleRoundGo(dst, src, rkey)
}
