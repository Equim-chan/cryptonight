package cryptonight

import (
	"golang.org/x/sys/cpu"
)

var (
	hasAVX = cpu.X86.HasAVX
)

func (cc *cache) v2Shuffle(offset uint64) {
	if hasAVX {
		v2ShuffleAsm(&cc.scratchpad[0], offset)
	} else {
		cc.v2ShuffleGo(offset)
	}
}

//go:nosplit
func v2ShuffleAsm(basePtr *uint64, offset uint64)
