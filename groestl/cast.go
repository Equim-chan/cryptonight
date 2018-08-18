package groestl

import (
	"reflect"
	"unsafe"
)

func u8u32Slice(a []uint8) []uint32 {
	targetLen := len(a) / 4
	targetCap := cap(a) / 4
	target := (*(*[]uint32)(unsafe.Pointer(&a)))

	header := (*reflect.SliceHeader)(unsafe.Pointer(&target))
	header.Len = targetLen
	header.Cap = targetCap

	return target
}

func u32u8Slice(a []uint32) []uint8 {
	targetLen := len(a) * 4
	targetCap := cap(a) * 4
	target := (*(*[]uint8)(unsafe.Pointer(&a)))

	header := (*reflect.SliceHeader)(unsafe.Pointer(&target))
	header.Len = targetLen
	header.Cap = targetCap

	return target
}
