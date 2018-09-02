// Package cryptonight implements CryptoNight hash function and some of its
// variant. Original CryptoNight algorithm is defined in CNS008 at
// https://cryptonote.org/cns/cns008.txt
package cryptonight // import "ekyu.moe/cryptonight"

import (
	"encoding/binary"
	"hash"
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
	cc := cachePool.Get().(*cache)
	sum := cc.sum(data, variant)
	cachePool.Put(cc)

	return sum
}

type cache struct {
	// DO NOT change the order of these fields in this struct!
	// They are carefully placed in this order to keep at least 64-bit aligned
	// for some fields.
	//
	// In the future the alignment may be set explicitly, see
	// https://github.com/golang/go/issues/19057

	scratchpad [2 * 1024 * 1024 / 8]uint64 // 2 MiB scratchpad for memhard loop
	finalState [25]uint64                  // state of keccak1600

	blocks [16]uint64 // temporary chunk/pointer of data
	rkeys  [40]uint32 // 10 rounds, instead of 14 as in standard AES-256
}

func (cc *cache) sum(data []byte, variant int) []byte {
	//////////////////////////////////////////////////
	// these variables never escape to heap
	var (
		// used in memory hard
		a, c, d [2]uint64
		b       [4]uint64 // variant 2 needs [4]uint64

		// for variant 1
		v1Tweak uint64

		// for variant 2
		divisionResult        uint64
		sqrtInput, sqrtResult uint64
	)

	//////////////////////////////////////////////////
	// as per CNS008 sec.3 Scratchpad Initialization
	sha3.Keccak1600State(&cc.finalState, data)

	if variant == 1 {
		// that's why data must have more than 43 bytes
		v1Tweak = cc.finalState[24] ^ binary.LittleEndian.Uint64(data[35:43])
	}

	// scratchpad init
	aes.CnExpandKey(cc.finalState[:4], &cc.rkeys)
	copy(cc.blocks[:], cc.finalState[8:24])

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			aes.CnRounds(cc.blocks[j:j+2], cc.blocks[j:j+2], &cc.rkeys)
		}
		copy(cc.scratchpad[i:i+16], cc.blocks[:16])
	}

	//////////////////////////////////////////////////
	// as per CNS008 sec.4 Memory-Hard Loop
	a[0] = cc.finalState[0] ^ cc.finalState[4]
	a[1] = cc.finalState[1] ^ cc.finalState[5]
	b[0] = cc.finalState[2] ^ cc.finalState[6]
	b[1] = cc.finalState[3] ^ cc.finalState[7]
	if variant == 2 {
		b[2] = cc.finalState[8] ^ cc.finalState[10]
		b[3] = cc.finalState[9] ^ cc.finalState[11]
		divisionResult = cc.finalState[12]
		sqrtResult = cc.finalState[13]
	}

	for i := 0; i < 524288; i++ {
		addr := (a[0] & 0x1ffff0) >> 3
		aes.CnSingleRound(c[:2], cc.scratchpad[addr:addr+2], &a)

		if variant == 2 {
			// since we use []uint64 instead of []uint8 as scratchpad, the offset applies too
			offset0 := addr ^ 0x02
			offset1 := addr ^ 0x04
			offset2 := addr ^ 0x06

			tmpChunk0 := cc.scratchpad[offset0]
			tmpChunk1 := cc.scratchpad[offset0+1]

			cc.scratchpad[offset0] = cc.scratchpad[offset2] + b[2]
			cc.scratchpad[offset0+1] = cc.scratchpad[offset2+1] + b[3]

			cc.scratchpad[offset2] = cc.scratchpad[offset1] + a[0]
			cc.scratchpad[offset2+1] = cc.scratchpad[offset1+1] + a[1]

			cc.scratchpad[offset1] = tmpChunk0 + b[0]
			cc.scratchpad[offset1+1] = tmpChunk1 + b[1]
		}

		cc.scratchpad[addr] = b[0] ^ c[0]
		cc.scratchpad[addr+1] = b[1] ^ c[1]

		if variant == 1 {
			t := cc.scratchpad[addr+1] >> 24
			t = ((^t)&1)<<4 | (((^t)&1)<<4&t)<<1 | (t&32)>>1
			cc.scratchpad[addr+1] ^= t << 24
		}

		addr = (c[0] & 0x1ffff0) >> 3
		d[0] = cc.scratchpad[addr]
		d[1] = cc.scratchpad[addr+1]

		if variant == 2 {
			// equivalent to VARIANT2_PORTABLE_INTEGER_MATH in slow-hash.c
			// VARIANT2_INTEGER_MATH_DIVISION_STEP
			d[0] ^= divisionResult ^ (sqrtResult << 32)
			divisor := (c[0]+(sqrtResult<<1))&0xffffffff | 0x80000001
			divisionResult = (c[1]/divisor)&0xffffffff | (c[1]%divisor)<<32
			sqrtInput = c[0] + divisionResult

			// VARIANT2_INTEGER_MATH_SQRT_STEP_FP64 and
			// VARIANT2_INTEGER_MATH_SQRT_FIXUP
			sqrtResult = v2Sqrt(sqrtInput)

			// shuffle again, it's the same process as above
			offset0 := addr ^ 0x02
			offset1 := addr ^ 0x04
			offset2 := addr ^ 0x06

			tmpChunk0 := cc.scratchpad[offset0]
			tmpChunk1 := cc.scratchpad[offset0+1]

			cc.scratchpad[offset0] = cc.scratchpad[offset2] + b[2]
			cc.scratchpad[offset0+1] = cc.scratchpad[offset2+1] + b[3]

			cc.scratchpad[offset2] = cc.scratchpad[offset1] + a[0]
			cc.scratchpad[offset2+1] = cc.scratchpad[offset1+1] + a[1]

			cc.scratchpad[offset1] = tmpChunk0 + b[0]
			cc.scratchpad[offset1+1] = tmpChunk1 + b[1]

			// re-asign higher-order of  b
			b[2] = b[0]
			b[3] = b[1]
		}

		// byteMul
		lo, hi := mul128(c[0], d[0])
		// byteAdd
		a[0] += hi
		a[1] += lo

		cc.scratchpad[addr] = a[0]
		cc.scratchpad[addr+1] = a[1]

		if variant == 1 {
			cc.scratchpad[addr+1] ^= v1Tweak
		}

		a[0] ^= d[0]
		a[1] ^= d[1]

		b[0] = c[0]
		b[1] = c[1]
	}

	//////////////////////////////////////////////////
	// as per CNS008 sec.5 Result Calculation
	aes.CnExpandKey(cc.finalState[4:8], &cc.rkeys)
	tmp := cc.finalState[8:24] // a temp pointer

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			cc.scratchpad[i+j] ^= tmp[j]
			cc.scratchpad[i+j+1] ^= tmp[j+1]
			aes.CnRounds(cc.scratchpad[i+j:i+j+2], cc.scratchpad[i+j:i+j+2], &cc.rkeys)
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
