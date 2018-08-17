package aes

func cnRoundsGo(dst, src []byte, rkeys []uint32) {
	var s0, s1, s2, s3, t0, t1, t2, t3 uint32

	s0 = uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	s1 = uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	s2 = uint32(src[8])<<24 | uint32(src[9])<<16 | uint32(src[10])<<8 | uint32(src[11])
	s3 = uint32(src[12])<<24 | uint32(src[13])<<16 | uint32(src[14])<<8 | uint32(src[15])

	for r := 0; r < 10; r++ {
		t0 = rkeys[4*r+0] ^ te0[uint8(s0>>24)] ^ te1[uint8(s1>>16)] ^ te2[uint8(s2>>8)] ^ te3[uint8(s3)]
		t1 = rkeys[4*r+1] ^ te0[uint8(s1>>24)] ^ te1[uint8(s2>>16)] ^ te2[uint8(s3>>8)] ^ te3[uint8(s0)]
		t2 = rkeys[4*r+2] ^ te0[uint8(s2>>24)] ^ te1[uint8(s3>>16)] ^ te2[uint8(s0>>8)] ^ te3[uint8(s1)]
		t3 = rkeys[4*r+3] ^ te0[uint8(s3>>24)] ^ te1[uint8(s0>>16)] ^ te2[uint8(s1>>8)] ^ te3[uint8(s2)]
		s0, s1, s2, s3 = t0, t1, t2, t3
	}

	dst[0], dst[1], dst[2], dst[3] = byte(s0>>24), byte(s0>>16), byte(s0>>8), byte(s0)
	dst[4], dst[5], dst[6], dst[7] = byte(s1>>24), byte(s1>>16), byte(s1>>8), byte(s1)
	dst[8], dst[9], dst[10], dst[11] = byte(s2>>24), byte(s2>>16), byte(s2>>8), byte(s2)
	dst[12], dst[13], dst[14], dst[15] = byte(s3>>24), byte(s3>>16), byte(s3>>8), byte(s3)
}

func cnSingleRoundGo(dst, src []byte, rkey []uint32) {
	var t0, t1, t2, t3 uint32

	t0 = rkey[0] ^ ter0[src[0]] ^ ter1[src[5]] ^ ter2[src[10]] ^ ter3[src[15]]
	t1 = rkey[1] ^ ter0[src[4]] ^ ter1[src[9]] ^ ter2[src[14]] ^ ter3[src[3]]
	t2 = rkey[2] ^ ter0[src[8]] ^ ter1[src[13]] ^ ter2[src[2]] ^ ter3[src[7]]
	t3 = rkey[3] ^ ter0[src[12]] ^ ter1[src[1]] ^ ter2[src[6]] ^ ter3[src[11]]

	dst[0], dst[1], dst[2], dst[3] = byte(t0), byte(t0>>8), byte(t0>>16), byte(t0>>24)
	dst[4], dst[5], dst[6], dst[7] = byte(t1), byte(t1>>8), byte(t1>>16), byte(t1>>24)
	dst[8], dst[9], dst[10], dst[11] = byte(t2), byte(t2>>8), byte(t2>>16), byte(t2>>24)
	dst[12], dst[13], dst[14], dst[15] = byte(t3), byte(t3>>8), byte(t3>>16), byte(t3>>24)
}
