// amd64 assembly implementation for memory hard step of variant 2, with SSE2 and AES-NI.

#include "textflag.h"
#include "sum_defs_amd64.h"

// func memhard2(cc *cache)
TEXT ·memhard2(SB), NOSPLIT, $16 // stack is used for the v2Sqrt CALL only
	MOVQ    cc+0(FP), STATE
	LEAQ    PAD_SIZE(STATE), AX  // *cc.finalState

	MOVO    0(AX), A
	PXOR    32(AX), A            // a = cc.finalState[0:2] ^ cc.finalState[4:6]
	MOVO    16(AX), B
	PXOR    48(AX), B            // b = cc.finalState[2:4] ^ cc.finalState[6:8]
	// <BEGIN> VARIANT2_INIT
	MOVO    64(AX), E
	PXOR    80(AX), E            // e = cc.finalState[8:10] ^ cc.finalState[10:12]
	MOVQ    96(AX), DIV_RESULT   // divResult = cc.finalState[12]
	MOVQ    104(AX), SQRT_RESULT // sqrtResult = cc.finalState[13]
	// <END> VARIANT2_INIT

	MOVQ    $ITER, I
LOOP:
	MOVQ    A, AX
	ANDQ    $0x1ffff0, AX        // addr = a[0] & 0x1ffff0
	LEAQ    0(STATE)(AX*1), CHUNK

	// single round of AES
	MOVO    0(CHUNK), C
	AESENC  A, C

	// <BEGIN> VARIANT2_SHUFFLE_ADD
	MOVQ    AX, BX
	MOVQ    AX, CX
	MOVQ    AX, DX
	XORQ    $0x10, BX
	XORQ    $0x20, CX
	XORQ    $0x30, DX
	LEAQ    0(STATE)(BX*1), BX
	LEAQ    0(STATE)(CX*1), CX
	LEAQ    0(STATE)(DX*1), DX
	MOVO    0(BX), TMPX0       // chunk0
	MOVO    0(CX), TMPX1       // chunk1
	MOVO    0(DX), TMPX2       // chunk2
	PADDQ   E, TMPX2
	PADDQ   B, TMPX0
	PADDQ   A, TMPX1
	MOVO    TMPX2, 0(BX)
	MOVO    TMPX0, 0(CX)
	MOVO    TMPX1, 0(DX)
	// <END> VARIANT2_SHUFFLE_ADD

	MOVO    B, TMPX0
	PXOR    C, TMPX0
	MOVO    TMPX0, 0(CHUNK)    // cc.scratchpad[addr:addr+2] = b ^ c

	MOVQ    C, TMP0
	ANDQ    $0x1ffff0, TMP0    // addr = c[0] & 0x1ffff0
	LEAQ    0(STATE)(TMP0*1), CHUNK
	MOVO    0(CHUNK), D

	// <BEGIN> VARIANT2_INTEGER_MATH_DIVISION_STEP
	MOVQ    D, BX
	MOVQ    SQRT_RESULT, CX
	SHLQ    $32, CX
	XORQ    DIV_RESULT, CX
	MOVQ    CX, TMPX0
	PXOR    TMPX0, D           // d[0] ^= divResult ^ (sqrtResult << 32)

	MOVQ    C, BX
	LEAL    0(BX)(SQRT_RESULT*2), CX
	ORL     $0x80000001, CX    // divisor = (c[0]+(sqrtResult<<1))&0xffffffff | 0x80000001

	MOVHLPS C, TMPX0
	MOVQ    TMPX0, AX
	XORQ    DX, DX
	DIVQ    CX
	SHLQ    $32, DX
	MOVL    AX, AX
	LEAQ    0(AX)(DX*1), DIV_RESULT // divResult = (c[1]/divisor)&0xffffffff | (c[1]%divisor)<<32

	LEAQ    0(BX)(DIV_RESULT*1), AX // sqrtInput = c[0] + divResult
	// <END> VARIANT2_INTEGER_MATH_DIVISION_STEP
	MOVQ    AX, 0(SP)
	CALL    ·v2Sqrt(SB)             // uses TMP1 and TMP2
	MOVQ    8(SP), SQRT_RESULT

	// byteMul
	MOVQ    C, AX
	MOVQ    D, BX
	MULQ    BX
	MOVQ    DX, TMPX3
	MOVQ    AX, TMPX0
	MOVLHPS TMPX0, TMPX3

	// <BEGIN> VARIANT2_SHUFFLE_ADD
	MOVQ    TMP0, BX
	MOVQ    TMP0, CX
	MOVQ    TMP0, DX
	XORQ    $0x10, BX
	XORQ    $0x20, CX
	XORQ    $0x30, DX
	LEAQ    0(STATE)(BX*1), BX
	LEAQ    0(STATE)(CX*1), CX
	LEAQ    0(STATE)(DX*1), DX
	MOVO    0(BX), TMPX0       // chunk0
	MOVO    0(CX), TMPX1       // chunk1
	MOVO    0(DX), TMPX2       // chunk2
	// <BEGIN> VARIANT2_2
	PXOR    TMPX3, TMPX0
	PXOR    TMPX1, TMPX3
	// <END> VARIANT2_2
	PADDQ   E, TMPX2
	PADDQ   B, TMPX0
	PADDQ   A, TMPX1
	MOVO    TMPX2, 0(BX)
	MOVO    TMPX0, 0(CX)
	MOVO    TMPX1, 0(DX)
	// <END> VARIANT2_SHUFFLE_ADD

	// byteAdd
	PADDQ   TMPX3, A

	MOVO    A, 0(CHUNK) // cc.scratchpad[addr:addr+2] = a
	PXOR    D, A        // a ^= d
	MOVO    B, E        // e = b
	MOVO    C, B        // b = c

	DECQ    I
	JNZ     LOOP
	RET
