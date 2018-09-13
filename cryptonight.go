// Package cryptonight implements CryptoNight hash function and some of its
// variant. Original CryptoNight algorithm is defined in CNS008 at
// https://cryptonote.org/cns/cns008.txt
package cryptonight // import "ekyu.moe/cryptonight"

import (
	"hash"
	"sync"
	"unsafe"

	"github.com/aead/skein"
	"github.com/dchest/blake256"

	"ekyu.moe/cryptonight/groestl"
	"ekyu.moe/cryptonight/jh"
)

var (
	// cachePool is a pool of cache.
	cachePool = sync.Pool{
		New: func() interface{} {
			return new(cache)
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

type cache struct {
	// DO NOT change the order of these fields in this struct!
	// They are carefully placed in this order to keep at least 16-byte aligned
	// for some fields.
	//
	// In the future the alignment may be set explicitly, see
	// https://github.com/golang/go/issues/19057

	scratchpad [2 * 1024 * 1024 / 8]uint64 // 2 MiB scratchpad for memhard loop
	finalState [25]uint64                  // state of keccak1600
	_          [8]byte                     // padded to keep 16-byte align (0x2000d0)

	blocks [16]uint64 // temporary chunk/pointer of data
	rkeys  [40]uint32 // 10 rounds, instead of 14 as in standard AES-256
}

func (cc *cache) finalHash() []byte {
	// the final hash
	hp := hashPool[cc.finalState[0]&0x03]
	h := hp.Get().(hash.Hash)
	h.Reset()
	h.Write((*[200]byte)(unsafe.Pointer(&cc.finalState))[:])
	sum := h.Sum(nil)
	hp.Put(h)

	return sum
}

// Sum calculate a CryptoNight hash digest. The return value is exactly 32 bytes
// long.
//
// When variant is 1, data is required to have at least 43 bytes.
// This is assumed and not checked by Sum. If this condition doesn't meet, Sum
// will panic straightforward.
func Sum(data []byte, variant int) []byte {
	cc := cachePool.Get().(*cache)
	sum := cc.sum(data, variant)
	cachePool.Put(cc)

	return sum
}
