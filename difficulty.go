package cryptonight

import (
	"math/big"
)

var (
	oneLsh256 = new(big.Int).Lsh(big.NewInt(1), 256)
	bigZero   = big.NewInt(0)
)

// Difficulty returns hash's difficulty. hash must be at least 32 bytes long,
// otherwise it will panic straightforward.
func Difficulty(hash []byte) uint64 {
	buf := make([]byte, 32)
	for i := 0; i < 16; i++ {
		buf[i], buf[31-i] = hash[31-i], hash[i]
	}

	hashBig := new(big.Int).SetBytes(buf)
	if hashBig.Cmp(bigZero) == 0 {
		return 0
	}

	return hashBig.Div(oneLsh256, hashBig).Uint64()
}
