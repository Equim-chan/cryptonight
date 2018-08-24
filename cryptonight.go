// Package cryptonight implements CryptoNight hash function and some of its
// variant. Original CryptoNight algorithm is defined in CNS008 at
// https://cryptonote.org/cns/cns008.txt
package cryptonight // import "ekyu.moe/cryptonight"

import (
	"encoding/binary"
	"hash"
	"math"
	"unsafe"

	"ekyu.moe/cryptonight/internal/aes"
	"ekyu.moe/cryptonight/internal/sha3"
)

// Sum calculate a CryptoNight hash digest. The return value is exactly 32 bytes
// long.
//
// When variant is 1, data is required to have at least 43 bytes.
// This is assumed and not checked by Sum. If this condition doesn't meet, Sum
// will panic straightforward.
func Sum(data []byte, variant int) []byte {
	cache := cachePool.Get().(*cache)
	sum := cache.sum(data, variant)
	cachePool.Put(cache)

	return sum
}

type cache struct {
	// DO NOT change the order of these fields in this struct!
	// They are carefully placed in this order to keep at least 64-bit aligned
	// for some fields.
	// In variant 2 which uses AVX for amd64, the scratchpad requires 128-bit
	// align to operate.
	//
	// In the future the alignment may be set explicitly, see
	// https://github.com/golang/go/issues/19057

	scratchpad [2 * 1024 * 1024 / 8]uint64 // 2 MiB scratchpad for memhard loop
	finalState [25]uint64                  // state of keccak1600

	blocks [16]uint64 // temporary chunk/pointer of data
	rkeys  [40]uint32 // 10 rounds, instead of 14 as in standard AES-256
}

func (cc *cache) sum(data []byte, variant int) []byte {
	// as per CNS008 sec.3 Scratchpad Initialization
	sha3.Keccak1600State(&cc.finalState, data)

	// for variant 1
	var tweak, t uint64
	if variant == 1 {
		// that's why data must have more than 43 bytes
		tweak = cc.finalState[24] ^ binary.LittleEndian.Uint64(data[35:43])
	}

	// for variant 2
	var (
		divisionResult, sqrtResult uint64
		dividend, divisor          uint64
	)

	// scratchpad init
	key := cc.finalState[:4]
	aes.CnExpandKey(key, &cc.rkeys)
	copy(cc.blocks[:], cc.finalState[8:24])

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			aes.CnRounds(cc.blocks[j:], cc.blocks[j:], &cc.rkeys)
		}
		copy(cc.scratchpad[i:], cc.blocks[:])
	}

	// as per CNS008 sec.4 Memory-Hard Loop
	var (
		a, b, c [2]uint64
		addr    uint64 // address index
	)
	a[0] = cc.finalState[0] ^ cc.finalState[4]
	a[1] = cc.finalState[1] ^ cc.finalState[5]
	b[0] = cc.finalState[2] ^ cc.finalState[6]
	b[1] = cc.finalState[3] ^ cc.finalState[7]
	for i := 0; i < 524288; i++ {
		addr = ((a[0]) & 0x1ffff0) >> 3
		aes.CnSingleRound(c[:], cc.scratchpad[addr:], &a)

		if variant == 2 {
			cc.v2Shuffle(addr)
		}

		cc.scratchpad[addr] = b[0] ^ c[0]
		cc.scratchpad[addr+1] = b[1] ^ c[1]
		b[0] = c[0]
		b[1] = c[1]

		if variant == 1 {
			t = cc.scratchpad[addr+1] >> 24
			t = ((^t)&1)<<4 | (((^t)&1)<<4&t)<<1 | (t&32)>>1
			cc.scratchpad[addr+1] ^= t << 24
		}

		addr = ((b[0]) & 0x1ffff0) >> 3
		c[0] = cc.scratchpad[addr]
		c[1] = cc.scratchpad[addr+1]

		if variant == 2 {
			c[1] ^= divisionResult ^ sqrtResult
			dividend = b[1]
			divisor = b[0]&0xffffffff | 0x80000001
			divisionResult = (dividend/divisor)&0xffffffff | ((dividend % divisor) << 32)
			sqrtResult = uint64(math.Sqrt(float64((b[0] + divisionResult) >> 16)))
		}

		// byteAdd and byteMul
		byteAddMul(&a, b[0], c[0])

		if variant == 2 {
			cc.v2Shuffle(addr)
		}

		cc.scratchpad[addr] = a[0]
		cc.scratchpad[addr+1] = a[1]
		a[0] ^= c[0]
		a[1] ^= c[1]

		if variant == 1 {
			cc.scratchpad[addr+1] ^= tweak
		}
	}

	// as per CNS008 sec.5 Result Calculation
	key = cc.finalState[4:8]
	aes.CnExpandKey(key, &cc.rkeys)
	tmp := cc.finalState[8:24]

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			cc.scratchpad[i+j] ^= tmp[j]
			cc.scratchpad[i+j+1] ^= tmp[j+1]
			aes.CnRounds(cc.scratchpad[i+j:], cc.scratchpad[i+j:], &cc.rkeys)
		}
		tmp = cc.scratchpad[i : i+16]
	}

	copy(cc.finalState[8:24], tmp)
	sha3.Keccak1600Permute(&cc.finalState)

	// the final hash
	hp := hashPool[cc.finalState[0]&0x03]
	h := hp.Get().(hash.Hash)
	h.Write((*[200]byte)(unsafe.Pointer(&cc.finalState[0]))[:])
	sum := h.Sum(nil)
	h.Reset()
	hp.Put(h)

	return sum
}
