package sha3

import (
	"encoding/binary"
	"unsafe"
)

func Keccak1600State(st *[200]byte, data []byte) {
	s := &state{rate: 136}
	s.Write(data)
	s.padAndPermute(0x01)

	for i := 0; i < 25; i++ {
		binary.LittleEndian.PutUint64(st[i*8:], s.a[i])
	}
}

func Keccak1600Permute(st *[200]byte) {
	keccakF1600((*[25]uint64)(unsafe.Pointer(st)))
}
