package cryptonight

import (
	"encoding/binary"

	"golang.org/x/sys/cpu"

	"ekyu.moe/cryptonight/internal/aes"
	"ekyu.moe/cryptonight/internal/sha3"
)

var (
	hasAES = cpu.X86.HasAES
)

func (cc *cache) sum(data []byte, variant int) []byte {
	if !hasAES {
		return cc.sumGo(data, variant)
	}
	return cc.sumAsm(data, variant)
}

func (cc *cache) sumAsm(data []byte, variant int) []byte {
	//////////////////////////////////////////////////
	// as per CNS008 sec.3 Scratchpad Initialization
	sha3.Keccak1600State(&cc.finalState, data)

	// scratchpad init
	aes.CnExpandKeyAsm(&cc.finalState[0], &cc.rkeys)
	copy(cc.blocks[:], cc.finalState[8:24])

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			aes.CnRoundsAsm(&cc.blocks[j], &cc.blocks[j], &cc.rkeys)
		}
		copy(cc.scratchpad[i:i+16], cc.blocks[:16])
	}

	//////////////////////////////////////////////////
	// as per CNS008 sec.4 Memory-Hard Loop
	switch variant {
	default:
		memhard0(cc)

	case 1:
		if len(data) < 43 {
			panic("cryptonight: variant 2 requires at least 43 bytes of input")
		}
		tweak := cc.finalState[24] ^ binary.LittleEndian.Uint64(data[35:43])
		memhard1(cc, tweak)

	case 2:
		memhard2(cc)
	}

	//////////////////////////////////////////////////
	// as per CNS008 sec.5 Result Calculation
	aes.CnExpandKeyAsm(&cc.finalState[4], &cc.rkeys)
	tmp := cc.finalState[8:24] // a temp pointer

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			cc.scratchpad[i+j+0] ^= tmp[j+0]
			cc.scratchpad[i+j+1] ^= tmp[j+1]
			aes.CnRoundsAsm(&cc.scratchpad[i+j], &cc.scratchpad[i+j], &cc.rkeys)
		}
		tmp = cc.scratchpad[i : i+16]
	}

	copy(cc.finalState[8:24], tmp)
	sha3.Keccak1600Permute(&cc.finalState)

	return cc.finalHash()
}

//go:noescape
func memhard0(cc *cache)

//go:noescape
func memhard1(cc *cache, tweak uint64)

//go:noescape
func memhard2(cc *cache)
