// amd64 assembly implementation for memory hard step of variant 1, with SSE2 and AES-NI.
// We don't use extra stack at all, and of course no CALL is made.

#include "textflag.h"
#include "sum_defs_amd64.h"

// func memhard1(cc *cache, tweak uint64)
TEXT ·memhard1(SB), NOSPLIT, $0
	MOVQ    cc+0(FP), STATE
	LEAQ    PAD_SIZE(STATE), AX // *cc.finalState

	MOVO    0(AX), A
	PXOR    32(AX), A           // a = cc.finalState[0:2] ^ cc.finalState[4:6]
	MOVO    16(AX), B
	PXOR    48(AX), B           // b = cc.finalState[2:4] ^ cc.finalState[6:8]
	// <BEGIN> VARIANT1_INIT
	MOVQ    tweak+8(FP), TMPX0
	PXOR    TWEAK, TWEAK
	MOVLHPS TMPX0, TWEAK
	// <END> VARIANT1_INIT

	MOVQ    $ITER, I
LOOP:
	MOVQ    A, AX
	ANDQ    $0x1ffff0, AX       // addr = a[0] & 0x1ffff0
	LEAQ    0(STATE)(AX*1), CHUNK

	// single round of AES
	MOVO    0(CHUNK), C
	AESENC  A, C

	MOVO    B, TMPX0
	PXOR    C, TMPX0
	MOVO    TMPX0, 0(CHUNK)     // cc.scratchpad[addr:addr+2] = b ^ c

	// <BEGIN> VARIANT1_1
	MOVB    11(CHUNK), CL       // tmp = ((uint8_t*)chunk)[11]
	MOVB    CL, BL
	SHRB    $3, CL
	ANDB    $6, CL
	ANDB    $1, BL
	ORB     BL, CL
	SHLB    $1, CL              // index = (((tmp >> 3) & 6) | (tmp & 1)) << 1
	MOVL    $0x75310, DX        // table = 0x75310
	SHRL    CL, DX
	ANDL    $0x30, DX
	XORL    DX, 11(CHUNK)       // ((uint8_t*)chunk)[11] = tmp ^ ((table >> index) & 0x30)
	// <END> VARIANT1_1

	MOVQ    C, AX
	MOVQ    AX, BX
	ANDQ    $0x1ffff0, BX       // addr = c[0] & 0x1ffff0
	LEAQ    0(STATE)(BX*1), CHUNK
	MOVO    0(CHUNK), D

	// byteMul
	MOVQ    D, BX
	MULQ    BX
	MOVQ    DX, TMPX0
	MOVQ    AX, TMPX1
	MOVLHPS TMPX1, TMPX0
	// byteAdd
	PADDQ   TMPX0, A

	// <BEGIN> VARIANT1_2
	MOVO    A, TMPX0
	PXOR    TWEAK, TMPX0
	// <END> VARIANT1_2

	MOVO    TMPX0, 0(CHUNK) // cc.scratchpad[addr:addr+2] = a; cc.scratchpad[addr+1] ^= tweak
	PXOR    D, A            // a ^= d
	MOVO    C, B            // b = c

	DECQ    I
	JNZ     LOOP
	RET
