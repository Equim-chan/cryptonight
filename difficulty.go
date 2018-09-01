package cryptonight

import (
	"encoding/binary"
	"math"
	"math/big"
)

var (
	oneLsh256 = new(big.Int).Lsh(big.NewInt(1), 256)
	bigZero   = big.NewInt(0)
)

// Difficulty returns hash's difficulty. hash must be at least 32 bytes long,
// otherwise it will panic straightforward.
//
// Difficulty is slower than CheckHash, so it should only be used when necessary.
//
// This isn't a part of CryptoNight, but since such demand of checking difficulty
// is too common, it is thus included in this package.
func Difficulty(hash []byte) uint64 {
	// swap byte order, since SetBytes accepts big instead of little endian
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

// CheckHash checks hash's difficulty against diff. It returns true if hash's
// difficulty is equal to or greater than diff. hash must be at least 32 bytes
// long, otherwise it will panic straightforward.
//
// CheckHash should be prefered over Difficulty if you only want to check if some
// hash passes a specific difficulty, as CheckHash is very fast and requires
// no heap allocation. It actually checks (hashDiff * diff) < 2^256 instead of
// calculating the exact value of hashDiff.
//
// This function is a port of monero: src/cryptonote_basic/difficulty.cpp:check_hash
//
// This isn't a part of CryptoNight, but since such demand of checking difficulty
// is too common, it is thus included in this package.
func CheckHash(hash []byte, diff uint64) bool {
	var low, high, top, cur, word uint64

	word = binary.LittleEndian.Uint64(hash[24:])
	top, high = mul128(word, diff)
	if high != 0 {
		return false
	}

	word = binary.LittleEndian.Uint64(hash)
	low, cur = mul128(word, diff)
	word = binary.LittleEndian.Uint64(hash[8:])
	low, high = mul128(word, diff)

	carry := cur+low < cur
	cur = high

	word = binary.LittleEndian.Uint64(hash[16:])
	low, high = mul128(word, diff)

	carry = cur+low < cur || (carry && cur+low == math.MaxUint64)
	carry = high+top < high || (carry && high+top == math.MaxUint64)

	return !carry
}
