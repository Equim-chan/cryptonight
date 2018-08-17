package aes

// CnExpandKey expands exactly 10 round keys.
//
// The result may vary from different architecture, but the output parameter
// rkeys is guranteed to give correct result when used as input in CnRounds.
//
// Note that this is CryptoNight specific.
// This is non-standard AES!
func CnExpandKey(key []byte, rkeys []uint32) {
	cnExpandKey(key, rkeys)
}

// CnRounds = (SubBytes, ShiftRows, MixColumns, AddRoundKey) * 10,
//
// dst and src must be at least 16 bytes long.
// rkeys must has at least 40 elements.
//
// Note that this is CryptoNight specific.
// This is non-standard AES!
func CnRounds(dst, src []byte, rkeys []uint32) {
	cnRounds(dst, src, rkeys)
}

// CnSingleRound performs exactly one AES round, i.e.
// one (SubBytes, ShiftRows, MixColumns, AddRoundKey).
//
// dst and src must be at least 16 bytes long.
// rkeys must has at least 40 elements.
//
// Note that this is CryptoNight specific.
// CnSingleRound * 10 might not be equivalent to one CnRounds.
func CnSingleRound(dst, src []byte, rkey []uint32) {
	cnSingleRound(dst, src, rkey)
}
