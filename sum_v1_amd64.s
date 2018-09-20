// amd64 assembly implementation for memory hard step of variant 1, with SSE2 and AES-NI.
// We don't use extra stack at all, and of course no CALL is made.

#include "textflag.h"
#include "sum_defs_amd64.h"

// func memhard1(cc *cache, tweak uint64)
TEXT ·memhard1(SB), NOSPLIT, $0
	MOVQ    cc+0(FP), _cc
	LEAQ    0x200000(_cc), AX  // *cc.finalState

	MOVO    0(AX), _a
	PXOR    32(AX), _a         // a = cc.finalState[0:2] ^ cc.finalState[4:6]

	MOVO    16(AX), _b
	PXOR    48(AX), _b         // b = cc.finalState[2:4] ^ cc.finalState[6:8]

	// <BEGIN> VARIANT1_INIT
	MOVQ    tweak+8(FP), _tmpX0
	PXOR    _tweak, _tweak
	MOVLHPS _tmpX0, _tweak
	// <END> VARIANT1_INIT
	MOVQ    $0x80000, _i
ITER:
	MOVQ    _a, AX
	ANDQ    $0x1ffff0, AX      // addr = a[0] & 0x1ffff0
	LEAQ    0(_cc)(AX*1), _pad

	// single round of AES
	MOVO    0(_pad), _c
	AESENC  _a, _c

	MOVO    _b, _tmpX0
	PXOR    _c, _tmpX0
	MOVO    _tmpX0, 0(_pad)    // cc.scratchpad[addr:addr+2] = b ^ c

	// <BEGIN> VARIANT1_1
	MOVB    11(_pad), CL       // tmp = ((uint8_t*)_pad)[11]
	MOVB    CL, BL
	SHRB    $3, CL
	ANDB    $6, CL
	ANDB    $1, BL
	ORB     BL, CL
	SHLB    $1, CL             // index = (((tmp >> 3) & 6) | (tmp & 1)) << 1
	MOVL    $0x75310, DX       // table = 0x75310
	SHRL    CL, DX
	ANDL    $0x30, DX
	XORL    DX, 11(_pad)       // ((uint8_t*)_pad)[11] = tmp ^ ((table >> index) & 0x30)
	// <END> VARIANT1_1

	MOVQ    _c, AX
	MOVQ    AX, BX
	ANDQ    $0x1ffff0, BX      // addr = c[0] & 0x1ffff0
	LEAQ    0(_cc)(BX*1), _pad
	MOVO    0(_pad), _d

	// byteMul
	MOVQ    _d, BX
	MULQ    BX
	MOVQ    DX, _tmpX0
	MOVQ    AX, _tmpX1
	MOVLHPS _tmpX1, _tmpX0
	// byteAdd
	PADDQ   _tmpX0, _a

	// <BEGIN> VARIANT1_2
	MOVO    _a, _tmpX0
	PXOR    _tweak, _tmpX0
	// <END> VARIANT1_2

	MOVO    _tmpX0, 0(_pad) // cc.scratchpad[addr:addr+2] = a
	PXOR    _d, _a  // a ^= d
	MOVO    _c, _b  // b = c

	DECQ    _i
	JNZ     ITER
	RET
