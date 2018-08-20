package cryptonight

import "unsafe"

func (cache *Cache) v2ShuffleGo(offset uint64) {
	// each chunk has 16 bytes, or 8 group of 2-bytes
	chunk0 := ((*[8]uint16)(unsafe.Pointer(&cache.scratchpad[offset^0x02])))
	chunk1 := ((*[8]uint16)(unsafe.Pointer(&cache.scratchpad[offset^0x04])))
	chunk2 := ((*[8]uint16)(unsafe.Pointer(&cache.scratchpad[offset^0x06])))

	// Shuffle modification
	//   ( 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23) ->
	//   (18 22 19 23 16 17 20 21 2 5 3 4 6 7 0 1 9 13  8 12 10 11 14 15)
	// See https://github.com/SChernykh/xmr-stak-cpu/blob/master/README.md for details
	chunk0[0], chunk0[1], chunk0[2], chunk0[3],
		chunk0[4], chunk0[5], chunk0[6], chunk0[7],
		chunk1[0], chunk1[1], chunk1[2], chunk1[3],
		chunk1[4], chunk1[5], chunk1[6], chunk1[7],
		chunk2[0], chunk2[1], chunk2[2], chunk2[3],
		chunk2[4], chunk2[5], chunk2[6], chunk2[7] =
		chunk2[2], chunk2[6], chunk2[3], chunk2[7],
		chunk2[0], chunk2[1], chunk2[4], chunk2[5],
		chunk0[2], chunk0[5], chunk0[3], chunk0[4],
		chunk0[6], chunk0[7], chunk0[0], chunk0[1],
		chunk1[1], chunk1[5], chunk1[0], chunk1[4],
		chunk1[2], chunk1[3], chunk1[6], chunk1[7]
}
