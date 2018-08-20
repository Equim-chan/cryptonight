package cryptonight

import (
	"golang.org/x/sys/cpu"
)

var (
	hasAVX = cpu.X86.HasAVX
)

func (cache *Cache) v2Shuffle(offset uint64) {
	if hasAVX {
		v2ShuffleAsm(&cache.scratchpad[0], offset)
	} else {
		cache.v2ShuffleGo(offset)
	}
}

//go:nosplit
func v2ShuffleAsm(basePtr *uint64, offset uint64)
