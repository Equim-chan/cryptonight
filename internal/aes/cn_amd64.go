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
		CnExpandKeyAsm(&key[0], rkeys)
	}
}

func cnRounds(dst, src []uint64, rkeys *[40]uint32) {
	if !hasAES {
		cnRoundsGo(dst, src, rkeys)
	} else {
		CnRoundsAsm(&dst[0], &src[0], rkeys)
	}
}

func cnSingleRound(dst, src []uint64, rkey *[2]uint64) {
	if !hasAES {
		cnSingleRoundGo(dst, src, rkey)
	} else {
		CnSingleRoundAsm(&dst[0], &src[0], rkey)
	}
}

//go:noescape
func CnExpandKeyAsm(src *uint64, rkey *[40]uint32)

//go:noescape
func CnRoundsAsm(dst, src *uint64, rkeys *[40]uint32)

//go:noescape
func CnSingleRoundAsm(dst, src *uint64, rkey *[2]uint64)
