// amd64 assembly implementation for memory hard step of variant 2, with SSE2 and AES-NI.

#include "textflag.h"
#include "sum_defs_amd64.h"

// func memhard2(cc *cache)
TEXT ·memhard2(SB), NOSPLIT, $16
    MOVQ    cc+0(FP), _cc
    LEAQ    0x200000(_cc), AX  // *cc.finalState

    MOVO    0(AX), _a
    PXOR    32(AX), _a         // a = cc.finalState[0:2] ^ cc.finalState[4:6]

    MOVO    16(AX), _b
    PXOR    48(AX), _b         // b = cc.finalState[2:4] ^ cc.finalState[6:8]

    // <BEGIN> VARIANT2_INIT
    MOVO    64(AX), _e
    PXOR    80(AX), _e               // e = cc.finalState[8:10] ^ cc.finalState[10:12]
    MOVQ    96(AX), _division_result // divisionResult = cc.finalState[12]
    MOVQ    104(AX), _sqrt_result    // sqrtResult = cc.finalState[13]
    // <END> VARIANT2_INIT

    MOVQ    $0x80000, _i
ITER:
    MOVQ    _a, AX
    ANDQ    $0x1ffff0, AX      // addr = a[0] & 0x1ffff0
    LEAQ    0(_cc)(AX*1), _pad

    // single round of AES
    MOVO    0(_pad), _c
    AESENC  _a, _c

    // <BEGIN> VARIANT2_SHUFFLE_ADD
    MOVQ    AX, BX
    XORQ    $0x10, BX
    LEAQ    0(_cc)(BX*1), BX
    MOVO    0(BX), _tmpX0     // chunk0
    MOVQ    AX, CX
    XORQ    $0x20, CX
    LEAQ    0(_cc)(CX*1), CX
    MOVO    0(CX), _tmpX1     // chunk1
    MOVQ    AX, DX
    XORQ    $0x30, DX
    LEAQ    0(_cc)(DX*1), DX
    MOVO    0(DX), _tmpX2     // chunk2

    PADDQ   _e, _tmpX2
    PADDQ   _b, _tmpX0
    PADDQ   _a, _tmpX1

    MOVO    _tmpX2, 0(BX)
    MOVO    _tmpX0, 0(CX)
    MOVO    _tmpX1, 0(DX)
    // <END> VARIANT2_SHUFFLE_ADD

    MOVO    _b, _tmpX0
    PXOR    _c, _tmpX0
    MOVO    _tmpX0, 0(_pad)    // cc.scratchpad[addr:addr+2] = b ^ c

    MOVQ    _c, _tmp0
    ANDQ    $0x1ffff0, _tmp0   // addr = c[0] & 0x1ffff0
    LEAQ    0(_cc)(_tmp0*1), _pad
    MOVO    0(_pad), _d

    // <BEGIN> VARIANT2_INTEGER_MATH_DIVISION_STEP
    MOVQ    _d, BX             // d[0]
    MOVQ    _sqrt_result, CX
    SHLQ    $32, CX
    XORQ    _division_result, CX
    XORQ    CX, BX
    // TODO：replace with PSHUFHW?
    MOVQ    BX, _tmpX0
    MOVLHPS _tmpX0, _tmpX0
    MOVHLPS _tmpX0, _d

    MOVL    _c, CX
    LEAL    0(CX)(_sqrt_result*2), CX
    ORL     $0x80000001, CX    // divisor = (c[0]+(sqrtResult<<1))&0xffffffff | 0x80000001

    MOVHLPS _c, _tmpX0
    MOVQ    _tmpX0, AX
    XORQ    DX, DX
    DIVQ    CX
    SHLQ    $32, DX
    MOVL    AX, AX
    LEAQ    0(AX)(DX*1), _division_result    // divisionResult = (c[1]/divisor)&0xffffffff | (c[1]%divisor)<<32

    MOVQ    X2, CX
    LEAQ    0(CX)(_division_result*1), AX // sqrtInput = c[0] + divisionResult
    // <END> VARIANT2_INTEGER_MATH_DIVISION_STEP
    MOVQ    AX, 0(SP)
    CALL    ·v2Sqrt(SB)
    MOVQ    8(SP), _sqrt_result

    // <BEGIN> VARIANT2_SHUFFLE_ADD
    MOVQ    _tmp0, BX
    XORQ    $0x10, BX
    LEAQ    0(_cc)(BX*1), BX
    MOVO    0(BX), _tmpX0     // chunk0
    MOVQ    _tmp0, CX
    XORQ    $0x20, CX
    LEAQ    0(_cc)(CX*1), CX
    MOVO    0(CX), _tmpX1     // chunk1
    MOVQ    _tmp0, DX
    XORQ    $0x30, DX
    LEAQ    0(_cc)(DX*1), DX
    MOVO    0(DX), _tmpX2     // chunk2

    PADDQ   _e, _tmpX2
    PADDQ   _b, _tmpX0
    PADDQ   _a, _tmpX1

    MOVO    _tmpX2, 0(BX)
    MOVO    _tmpX0, 0(CX)
    MOVO    _tmpX1, 0(DX)
    // <END> VARIANT2_SHUFFLE_ADD
    MOVO    _b, _e  // e = b

    // byteMul
    MOVQ    _c, AX
    MOVQ    _d, BX
    MULQ    BX
    // byteAdd
    MOVQ    _a, BX  // a[0]
    MOVHLPS _a, _a
    MOVQ    _a, CX  // a[1]
    ADDQ    DX, BX
    ADDQ    AX, CX
    MOVQ    BX, _a
    MOVQ    CX, _tmpX0
    MOVLHPS _tmpX0, _a

    MOVO    _a, 0(_pad)  // cc.scratchpad[addr:addr+2] = a
    PXOR    _d, _a       // a ^= d
    MOVO    _c, _b       // b = c

    DECQ    _i
    JNZ     ITER
    RET
