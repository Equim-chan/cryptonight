package cryptonight

import (
	"math"
)

func v2Sqrt(in uint64) uint64 {
	out := uint64(
		math.Sqrt(
			float64(in)+1<<64,
		)*2 - 1<<33,
	)

	s := out >> 1
	b := out & 1
	r := s*(s+b) + (out << 32)
	if r+b > in {
		out--
	}

	// NOTE: the following branch does not seem to be able to be covered,
	//   i.e. it works without the code below.
	//   In case you find any issue, try de-commenting these.

	// if r+1<<32 < in-s {
	// 	out++
	// }

	return out
}
