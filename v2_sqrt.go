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
	r := s*(s+b) + (out << 32) - in
	if int64(r+b) > 0 {
		out--
	}
	if int64(r+s+(1<<32)) < 0 {
		out++
	}

	return out
}
