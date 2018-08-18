package aes

import (
	"unsafe"
)

func cnExpandKeyGo(key []uint64, rkeys *[40]uint32) {
	for i := 0; i < 4; i++ {
		rkeys[2*i] = uint32(key[i]&0xff<<24) | uint32(key[i]&0xff00<<8) | uint32(key[i]&0xff0000>>8) | uint32(key[i]&0xff000000>>24)
		rkeys[2*i+1] = uint32(key[i]&0xff00000000>>8) | uint32(key[i]&0xff0000000000>>24) | uint32(key[i]&0xff000000000000>>40) | uint32(key[i]&0xff00000000000000>>56)
	}

	for i := 8; i < 40; i++ {
		t := rkeys[i-1]
		if i%8 == 0 {
			t = subw(rotw(t)) ^ (uint32(powx[i/8-1]) << 24)
		} else if 8 > 6 && i%8 == 4 {
			t = subw(t)
		}
		rkeys[i] = rkeys[i-8] ^ t
	}
}

func cnRoundsGo(dst, src []uint64, rkeys *[40]uint32) {
	src8 := (*[16]byte)(unsafe.Pointer(&src[0]))
	dst8 := (*[16]byte)(unsafe.Pointer(&dst[0]))

	var s0, s1, s2, s3, t0, t1, t2, t3 uint32

	s0 = uint32(src8[0])<<24 | uint32(src8[1])<<16 | uint32(src8[2])<<8 | uint32(src8[3])
	s1 = uint32(src8[4])<<24 | uint32(src8[5])<<16 | uint32(src8[6])<<8 | uint32(src8[7])
	s2 = uint32(src8[8])<<24 | uint32(src8[9])<<16 | uint32(src8[10])<<8 | uint32(src8[11])
	s3 = uint32(src8[12])<<24 | uint32(src8[13])<<16 | uint32(src8[14])<<8 | uint32(src8[15])

	for r := 0; r < 10; r++ {
		t0 = rkeys[4*r+0] ^ te0[uint8(s0>>24)] ^ te1[uint8(s1>>16)] ^ te2[uint8(s2>>8)] ^ te3[uint8(s3)]
		t1 = rkeys[4*r+1] ^ te0[uint8(s1>>24)] ^ te1[uint8(s2>>16)] ^ te2[uint8(s3>>8)] ^ te3[uint8(s0)]
		t2 = rkeys[4*r+2] ^ te0[uint8(s2>>24)] ^ te1[uint8(s3>>16)] ^ te2[uint8(s0>>8)] ^ te3[uint8(s1)]
		t3 = rkeys[4*r+3] ^ te0[uint8(s3>>24)] ^ te1[uint8(s0>>16)] ^ te2[uint8(s1>>8)] ^ te3[uint8(s2)]
		s0, s1, s2, s3 = t0, t1, t2, t3
	}

	dst8[0], dst8[1], dst8[2], dst8[3] = byte(s0>>24), byte(s0>>16), byte(s0>>8), byte(s0)
	dst8[4], dst8[5], dst8[6], dst8[7] = byte(s1>>24), byte(s1>>16), byte(s1>>8), byte(s1)
	dst8[8], dst8[9], dst8[10], dst8[11] = byte(s2>>24), byte(s2>>16), byte(s2>>8), byte(s2)
	dst8[12], dst8[13], dst8[14], dst8[15] = byte(s3>>24), byte(s3>>16), byte(s3>>8), byte(s3)
}

func cnSingleRoundGo(dst, src []uint64, rkey *[4]uint32) {
	src8 := (*[16]byte)(unsafe.Pointer(&src[0]))
	dst8 := (*[16]byte)(unsafe.Pointer(&dst[0]))

	var t0, t1, t2, t3 uint32

	t0 = rkey[0] ^ ter0[src8[0]] ^ ter1[src8[5]] ^ ter2[src8[10]] ^ ter3[src8[15]]
	t1 = rkey[1] ^ ter0[src8[4]] ^ ter1[src8[9]] ^ ter2[src8[14]] ^ ter3[src8[3]]
	t2 = rkey[2] ^ ter0[src8[8]] ^ ter1[src8[13]] ^ ter2[src8[2]] ^ ter3[src8[7]]
	t3 = rkey[3] ^ ter0[src8[12]] ^ ter1[src8[1]] ^ ter2[src8[6]] ^ ter3[src8[11]]

	dst8[0], dst8[1], dst8[2], dst8[3] = byte(t0), byte(t0>>8), byte(t0>>16), byte(t0>>24)
	dst8[4], dst8[5], dst8[6], dst8[7] = byte(t1), byte(t1>>8), byte(t1>>16), byte(t1>>24)
	dst8[8], dst8[9], dst8[10], dst8[11] = byte(t2), byte(t2>>8), byte(t2>>16), byte(t2>>24)
	dst8[12], dst8[13], dst8[14], dst8[15] = byte(t3), byte(t3>>8), byte(t3>>16), byte(t3>>24)
}
