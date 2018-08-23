package cryptonight

import (
	"sync"

	"github.com/aead/skein"
	"github.com/dchest/blake256"

	"ekyu.moe/cryptonight/groestl"
	"ekyu.moe/cryptonight/jh"
)

var (
	// cachePool is a pool of cache.
	cachePool = sync.Pool{
		New: func() interface{} {
			return &cache{
				blocks: make([]uint64, 16),
			}
		},
	}

	// hashPool is for final hashes
	hashPool = [...]*sync.Pool{
		{New: func() interface{} { return blake256.New() }},
		{New: func() interface{} { return groestl.New256() }},
		{New: func() interface{} { return jh.New256() }},
		{New: func() interface{} { return skein.New256(nil) }},
	}
)
