package cryptonight

import (
	"sync"

	"github.com/aead/skein"
	"github.com/dchest/blake256"

	"ekyu.moe/cryptonight/groestl"
	"ekyu.moe/cryptonight/jh"
)

// pool is a pool of cache.
var pool = sync.Pool{
	New: func() interface{} {
		return &cache{
			blocks: make([]uint64, 16),
		}
	},
}

var hashPool = []sync.Pool{
	{New: func() interface{} { return blake256.New() }},
	{New: func() interface{} { return groestl.New256() }},
	{New: func() interface{} { return jh.New256() }},
	{New: func() interface{} { return skein.New256(nil) }},
}
