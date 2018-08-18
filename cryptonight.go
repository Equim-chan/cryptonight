// HEAD_PLACEHOLDER
// +build ignore

// Package cryptonight implements CryptoNight hash function and some of its
// variant.
//
// ref: https://cryptonote.org/cns/cns008.txt
package cryptonight // import "ekyu.moe/cryptonight"

import (
	"encoding/binary"
	"hash"
	"runtime"
	"unsafe"

	"github.com/aead/skein"
	"github.com/dchest/blake256"

	"ekyu.moe/cryptonight/groestl"
	"ekyu.moe/cryptonight/internal/aes"
	"ekyu.moe/cryptonight/internal/sha3"
	"ekyu.moe/cryptonight/jh"
)

// This field is for macro definitions.
// We define it in a literal string so that it can trick gofmt(1).
//
// It should be empty after they are expanded by cpp(1).
const _ = `
#undef build
#undef ignore

#define U64_U8(a, begin, end) \
    ( (*[( (end) - (begin) ) * 8]uint8)(unsafe.Pointer(&a[ (begin) ])) )

#define U64_U32(a, begin, end) \
    ( (*[( (end) - (begin) ) * 2]uint32)(unsafe.Pointer(&a[ (begin) ])) )

#define TO_ADDR(a) (( (a[0]) & 0x1ffff0) >> 3)
`

// To trick goimports(1).
var _ = unsafe.Pointer(nil)

// Cache can reuse the memory chunks for potential multiple Sum calls. A Cache
// instance occupies at least 2,097,352 bytes in memory.
//
// cache.Sum is not concurrent safe. A Cache only allows at most one Sum running.
// If you intend to call cache.Sum it concurrently, you should either create
// multiple Cache instances (recommended for mining apps), or use a sync.Pool to
// manage multiple Cache instances (recommended for mining pools).
//
//
// Example for multiple instances (mining app):
//      n := runtime.GOMAXPROCS()
//      c := make([]*cryptonight.Cached, n)
//      for i := 0; i < n; i++ {
//          c[i] = new(cryptonight.Cached)
//      }
//
//      // ...
//      for _, v := range c {
//          go func() {
//              for {
//                  sum := v.Sum(data, 1)
//                  // do something with sum...
//              }
//          }()
//      }
//      // ...
//
//
// Example for sync.Pool (mining pool):
//      cachePool := sync.Pool{
//          New: func() interface{} {
//              return new(cryptonight.Cache)
//          },
//      }
//
//      // ...
//      data := <-share // received from some miner
//      if len(data) < 43 { // input for variant 1 must be longer than 43 bytes
//      	// ...
//      	return
//      }
//      cache := cachePool.Get().(*cryptonight.Cache)
//      sum := cache.Sum(data, 1)
//      cachePool.Put(cache) // a Cache is not used after Sum.
//      // do something with sum...
//
// The zero value for Cache is ready to use.
type Cache struct {
	finalState [25]uint64                  // state of keccak1600
	scratchpad [2 * 1024 * 1024 / 8]uint64 // 2 MiB scratchpad for memhard loop
}

// Sum calculate a CryptoNight hash digest. The return value is exactly 32 bytes
// long.
//
// Note that if variant is 1, then data is required to have at least 43 bytes.
// This is assumed and not checked by Sum. If such condition doesn't meet, Sum
// will panic.
func (cache *Cache) Sum(data []byte, variant int) []byte {
	// as per cns008 sec.3 Scratchpad Initialization
	sha3.Keccak1600State(&cache.finalState, data)

	tweak := uint64(0)
	if variant == 1 {
		// that's why data must have more than 43 bytes
		tweak = cache.finalState[24] ^ binary.LittleEndian.Uint64(data[35:43])
	}

	key := cache.finalState[:4]
	rkeys := new([40]uint32) // 10 rounds, instead of 14 as in standard AES-256
	aes.CnExpandKey(key, rkeys)
	blocks := make([]uint64, 16)
	copy(blocks, cache.finalState[8:24])

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			aes.CnRounds(blocks[j:], blocks[j:], rkeys)
		}
		copy(cache.scratchpad[i:], blocks)
	}

	// as per cns008 sec.4 Memory-Hard Loop
	a, b := new([2]uint64), new([2]uint64)
	c, d := new([2]uint64), new([2]uint64)
	product := new([2]uint64) // product in byteMul step
	addr := uint64(0)         // address index
	t := uint64(0)            // for variant 1

	a[0] = cache.finalState[0] ^ cache.finalState[4]
	a[1] = cache.finalState[1] ^ cache.finalState[5]
	b[0] = cache.finalState[2] ^ cache.finalState[6]
	b[1] = cache.finalState[3] ^ cache.finalState[7]

	for i := 0; i < 524288; i++ {
		addr = TO_ADDR(a)
		aes.CnSingleRound(c[:], cache.scratchpad[addr:], U64_U32(a, 0, 2))
		cache.scratchpad[addr] = b[0] ^ c[0]
		cache.scratchpad[addr+1] = b[1] ^ c[1]
		b[0], b[1] = c[0], c[1]

		if variant == 1 {
			t = cache.scratchpad[addr+1] >> 24
			t = ((^t)&1)<<4 | (((^t)&1)<<4&t)<<1 | (t&32)>>1
			cache.scratchpad[addr+1] ^= t << 24
		}

		addr = TO_ADDR(c)
		d[0] = cache.scratchpad[addr]
		d[1] = cache.scratchpad[addr+1]
		byteMul(product, c[0], d[0])
		// byteAdd
		a[0] += product[0]
		a[1] += product[1]

		cache.scratchpad[addr] = a[0]
		cache.scratchpad[addr+1] = a[1]
		a[0] ^= d[0]
		a[1] ^= d[1]

		if variant == 1 {
			cache.scratchpad[addr+1] ^= tweak
		}
	}

	// as per cns008 sec.5 Result Calculation
	key = cache.finalState[4:8]
	aes.CnExpandKey(key, rkeys)
	blocks = cache.finalState[8:24]

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			cache.scratchpad[i+j] ^= blocks[j]
			cache.scratchpad[i+j+1] ^= blocks[j+1]
			aes.CnRounds(cache.scratchpad[i+j:], cache.scratchpad[i+j:], rkeys)
		}
		blocks = cache.scratchpad[i : i+16]
	}

	copy(cache.finalState[8:24], blocks)

	// This KeepAlive is a must, as we hacked too much for memory.
	runtime.KeepAlive(cache.finalState)
	sha3.Keccak1600Permute(&cache.finalState)

	var h hash.Hash
	switch cache.finalState[0] & 0x03 {
	case 0x00:
		h = blake256.New()
	case 0x01:
		h = groestl.New256()
	case 0x02:
		h = jh.New256()
	default:
		h = skein.New256(nil)
	}
	h.Write(U64_U8(cache.finalState, 0, 25)[:])

	return h.Sum(nil)
}

// Sum calculate a CryptoNight hash digest. The return value is exactly 32 bytes
// long.
//
// Note that if variant is 1, then data is required to have at least 43 bytes.
// This is assumed and not checked by Sum. If such condition doesn't meet, Sum
// will panic.
//
// Sum is not recommended for a large scale of calls as it consumes a large
// amount of memory. In such scenario, consider using Cache instead.
func Sum(data []byte, variant int) []byte {
	return new(Cache).Sum(data, variant)
}
