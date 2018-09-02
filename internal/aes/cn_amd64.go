package aes

import (
	"golang.org/x/sys/cpu"
)

var (
	hasAES = cpu.X86.HasAES
)

func cnExpandKey(key []uint64, rkeys *[40]uint32) {
	if !hasAES {
		cnExpandKeyGo(key, rkeys)
	} else {
		cnExpandKeyAsm(&key[0], rkeys)
	}
}

func cnRounds(dst, src []uint64, rkeys *[40]uint32) {
	if !hasAES {
		cnRoundsGo(dst, src, rkeys)
	} else {
		cnRoundsAsm(&dst[0], &src[0], rkeys)
	}
}

func cnSingleRound(dst, src []uint64, rkey *[2]uint64) {
	if !hasAES {
		cnSingleRoundGo(dst, src, rkey)
	} else {
		cnSingleRoundAsm(&dst[0], &src[0], rkey)
	}
}

//go:noescape
func cnExpandKeyAsm(src *uint64, rkey *[40]uint32)

//go:noescape
func cnRoundsAsm(dst, src *uint64, rkeys *[40]uint32)

//go:noescape
func cnSingleRoundAsm(dst, src *uint64, rkey *[2]uint64)
