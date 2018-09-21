package cryptonight

import (
	"encoding/binary"

	"ekyu.moe/cryptonight/internal/aes"
	"ekyu.moe/cryptonight/internal/sha3"
)

func (cc *cache) sumGo(data []byte, variant int) []byte {
	//////////////////////////////////////////////////
	// these variables never escape to heap
	var (
		// used in memory hard
		a, b, c, d [2]uint64

		// for variant 1
		v1Tweak uint64

		// for variant 2
		e          [2]uint64
		divResult  uint64
		sqrtResult uint64
	)

	//////////////////////////////////////////////////
	// as per CNS008 sec.3 Scratchpad Initialization
	sha3.Keccak1600State(&cc.finalState, data)

	if variant == 1 {
		if len(data) < 43 {
			panic("cryptonight: variant 2 requires at least 43 bytes of input")
		}
		v1Tweak = cc.finalState[24] ^ binary.LittleEndian.Uint64(data[35:43])
	}

	// scratchpad init
	aes.CnExpandKeyGo(cc.finalState[:4], &cc.rkeys)
	copy(cc.blocks[:], cc.finalState[8:24])

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			aes.CnRoundsGo(cc.blocks[j:j+2], cc.blocks[j:j+2], &cc.rkeys)
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
		e[0] = cc.finalState[8] ^ cc.finalState[10]
		e[1] = cc.finalState[9] ^ cc.finalState[11]
		divResult = cc.finalState[12]
		sqrtResult = cc.finalState[13]
	}

	for i := 0; i < 524288; i++ {
		addr := (a[0] & 0x1ffff0) >> 3
		aes.CnSingleRoundGo(c[:2], cc.scratchpad[addr:addr+2], &a)

		if variant == 2 {
			// since we use []uint64 instead of []uint8 as scratchpad, the offset applies too
			offset0 := addr ^ 0x02
			offset1 := addr ^ 0x04
			offset2 := addr ^ 0x06

			chunk0_0 := cc.scratchpad[offset0+0]
			chunk0_1 := cc.scratchpad[offset0+1]
			chunk1_0 := cc.scratchpad[offset1+0]
			chunk1_1 := cc.scratchpad[offset1+1]
			chunk2_0 := cc.scratchpad[offset2+0]
			chunk2_1 := cc.scratchpad[offset2+1]

			cc.scratchpad[offset0+0] = chunk2_0 + e[0]
			cc.scratchpad[offset0+1] = chunk2_1 + e[1]
			cc.scratchpad[offset2+0] = chunk1_0 + a[0]
			cc.scratchpad[offset2+1] = chunk1_1 + a[1]
			cc.scratchpad[offset1+0] = chunk0_0 + b[0]
			cc.scratchpad[offset1+1] = chunk0_1 + b[1]
		}

		cc.scratchpad[addr+0] = b[0] ^ c[0]
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
			d[0] ^= divResult ^ (sqrtResult << 32)
			divisor := (c[0]+(sqrtResult<<1))&0xffffffff | 0x80000001
			divResult = (c[1]/divisor)&0xffffffff | (c[1]%divisor)<<32
			sqrtInput := c[0] + divResult

			// VARIANT2_INTEGER_MATH_SQRT_STEP_FP64 and
			// VARIANT2_INTEGER_MATH_SQRT_FIXUP
			sqrtResult = v2Sqrt(sqrtInput)
		}

		// byteMul
		lo, hi := mul128(c[0], d[0])

		if variant == 2 {
			// shuffle again, it's the same process as above
			offset0 := addr ^ 0x02
			offset1 := addr ^ 0x04
			offset2 := addr ^ 0x06

			chunk0_0 := cc.scratchpad[offset0+0]
			chunk0_1 := cc.scratchpad[offset0+1]
			chunk1_0 := cc.scratchpad[offset1+0]
			chunk1_1 := cc.scratchpad[offset1+1]
			chunk2_0 := cc.scratchpad[offset2+0]
			chunk2_1 := cc.scratchpad[offset2+1]

			// VARIANT2_2
			chunk0_0 ^= hi
			chunk0_1 ^= lo
			hi ^= chunk1_0
			lo ^= chunk1_1

			cc.scratchpad[offset0+0] = chunk2_0 + e[0]
			cc.scratchpad[offset0+1] = chunk2_1 + e[1]
			cc.scratchpad[offset2+0] = chunk1_0 + a[0]
			cc.scratchpad[offset2+1] = chunk1_1 + a[1]
			cc.scratchpad[offset1+0] = chunk0_0 + b[0]
			cc.scratchpad[offset1+1] = chunk0_1 + b[1]

			// re-asign higher-order of b
			e[0] = b[0]
			e[1] = b[1]
		}

		// byteAdd
		a[0] += hi
		a[1] += lo

		cc.scratchpad[addr+0] = a[0]
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
	aes.CnExpandKeyGo(cc.finalState[4:8], &cc.rkeys)
	tmp := cc.finalState[8:24] // a temp pointer

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			cc.scratchpad[i+j+0] ^= tmp[j+0]
			cc.scratchpad[i+j+1] ^= tmp[j+1]
			aes.CnRoundsGo(cc.scratchpad[i+j:i+j+2], cc.scratchpad[i+j:i+j+2], &cc.rkeys)
		}
		tmp = cc.scratchpad[i : i+16]
	}

	copy(cc.finalState[8:24], tmp)
	sha3.Keccak1600Permute(&cc.finalState)

	return cc.finalHash()
}
