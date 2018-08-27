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

	v2S := out >> 1
	v2B := out & 1
	v2R := v2S*(v2S+v2B) + (out << 32) - in
	if int64(v2R+v2B) > 0 {
		out--
	}
	if int64(v2R+v2S+(1<<32)) < 0 {
		out++
	}

	return out
}
