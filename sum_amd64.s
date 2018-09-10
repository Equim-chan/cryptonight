#include "textflag.h"

// We don't use extra stack at all, and of course no CALL is made.

// common
#define _cc    R8
#define _i     R9
#define _pad   R10
#define _a     X0
#define _b     X1
#define _c     X2
#define _d     X3

// variant 1
#define _tweak R11

// variant 2
#define _e     X4
#define _division_result R11
#define _sqrt_result R12

// tmp
#define _tmp0  R15
#define _tmp1  R14
#define _tmp2  R13
#define _tmpX0 X15
#define _tmpX1 X14
#define _tmpX2 X13

// func memhard0(cc *cache)
TEXT ·memhard0(SB), NOSPLIT, $0
    MOVQ    cc+0(FP), _cc
    LEAQ    0x200000(_cc), AX  // *cc.finalState

    MOVOU   0(AX), _tmpX0
    MOVOU   32(AX), _tmpX1
    PXOR    _tmpX0, _tmpX1
    MOVOU   _tmpX1, _a     // a = cc.finalState[0:2] ^ cc.finalState[4:6]

    MOVOU   16(AX), _tmpX0
    MOVOU   48(AX), _tmpX1
    PXOR    _tmpX0, _tmpX1
    MOVOU   _tmpX1, _b     // b = cc.finalState[2:4] ^ cc.finalState[6:8]

    MOVQ    $0x80000, _i
ITER:
    MOVQ    _a, AX
    ANDQ    $0x1ffff0, AX      // addr = a[0] & 0x1ffff0
    LEAQ    0(_cc)(AX*1), _pad

    // single round of AES
    MOVOU   0(_pad), _c
    AESENC  _a, _c

    MOVOU   _b, _tmpX0
    PXOR    _c, _tmpX0
    MOVOU   _tmpX0, 0(_pad)    // cc.scratchpad[addr:addr+2] = b ^ c

    MOVQ    _c, AX
    ANDQ    $0x1ffff0, AX      // addr = c[0] & 0x1ffff0
    LEAQ    0(_cc)(AX*1), _pad
    MOVOU   0(_pad), _d

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

    MOVOU   _a, 0(_pad)  // cc.scratchpad[addr:addr+2] = a
    PXOR    _d, _a       // a ^= d
    MOVOU   _c, _b       // b = c

    DECQ    _i
    JNZ     ITER
    RET


// func memhard1(cc *cache, tweak uint64)
TEXT ·memhard1(SB), NOSPLIT, $0
    MOVQ    cc+0(FP), _cc
    LEAQ    0x200000(_cc), AX  // *cc.finalState

    MOVOU   0(AX), _tmpX0
    MOVOU   32(AX), _tmpX1
    PXOR    _tmpX0, _tmpX1
    MOVOU   _tmpX1, _a     // a = cc.finalState[0:2] ^ cc.finalState[4:6]

    MOVOU   16(AX), _tmpX0
    MOVOU   48(AX), _tmpX1
    PXOR    _tmpX0, _tmpX1
    MOVOU   _tmpX1, _b     // b = cc.finalState[2:4] ^ cc.finalState[6:8]

/*** <BEGIN> VARIANT1_INIT ***/
    MOVQ    tweak+8(FP), _tweak
/*** <END> VARIANT1_INIT ***/
    MOVQ    $0x80000, _i
ITER:
    MOVQ    _a, AX
    ANDQ    $0x1ffff0, AX      // addr = a[0] & 0x1ffff0
    LEAQ    0(_cc)(AX*1), _pad

    // single round of AES
    MOVOU   0(_pad), _c
    AESENC  _a, _c

    MOVOU   _b, _tmpX0
    PXOR    _c, _tmpX0
    MOVOU   _tmpX0, 0(_pad)    // cc.scratchpad[addr:addr+2] = b ^ c

/*** <BEGIN> VARIANT1_1 ***/
    MOVB    11(_pad), CL  // tmp = ((uint8_t*)_pad)[11]
    MOVB    CL, BL
    SHRB    $3, CL
    ANDB    $6, CL
    ANDB    $1, BL
    ORB     BL, CL
    SHLB    $1, CL        // index = (((tmp >> 3) & 6) | (tmp & 1)) << 1
    MOVL    $0x75310, DX  // table = 0x75310
    SHRL    CL, DX
    ANDL    $0x30, DX
    XORL    DX, 11(_pad)  // ((uint8_t*)_pad)[11] = tmp ^ ((table >> index) & 0x30)
/*** <END> VARIANT1_1 ***/

    MOVQ    _c, AX
    ANDQ    $0x1ffff0, AX      // addr = c[0] & 0x1ffff0
    LEAQ    0(_cc)(AX*1), _pad
    MOVOU   0(_pad), _d

    // byteMul
    MOVQ    _c, AX
    MOVQ    _d, BX
    MULQ    BX
    // byteAdd
    MOVQ    _a, BX  // a[0]
    MOVHLPS _a, _a
    MOVQ    _a, CX  // a[1]
    ADDQ    AX, CX
    ADDQ    DX, BX
    MOVQ    BX, _a
    MOVQ    CX, _tmpX0
    MOVLHPS _tmpX0, _a

    MOVOU   _a, 0(_pad) // cc.scratchpad[addr:addr+2] = a
/*** <BEGIN> VARIANT1_2 ***/
    XORQ    _tweak, 8(_pad)
/*** <END> VARIANT1_2 ***/
    PXOR    _d, _a  // a ^= d
    MOVOU   _c, _b  // b = c

    DECQ    _i
    JNZ     ITER
    RET


#define V2_SQRT \
    \ /*** <BEGIN> VARIANT2_INTEGER_MATH_SQRT_STEP ***/
    MOVQ    _tmp1, AX            \ // _tmp1 accepted as sqrtInput
    SHRQ    $12, AX              \
    MOVQ    $0x3ff0000000000000, BX     \
    ADDQ    BX, AX               \
    MOVQ    AX, _tmpX0           \
    SQRTSD  _tmpX0, _tmpX0       \
    MOVQ    _tmpX0, _sqrt_result \
    SUBQ    BX, _sqrt_result     \ // sqrtResult is not yet sanitized
    \ /*** <END> VARIANT2_INTEGER_MATH_SQRT_STEP ***/
    \ /*** <BEGIN> VARIANT2_INTEGER_MATH_SQRT_FIXUP ***/
    SHRQ    $19, _sqrt_result    \
    MOVQ    _sqrt_result, AX     \
    SHRQ    $1, AX               \ // s = sqrtResult >> 1
    MOVQ    _sqrt_result, BX     \
    ANDQ    $1, BX               \ // b = sqrtResult & 1
    MOVQ    _sqrt_result, CX     \
    SHLQ    $32, CX              \
    LEAQ    0(AX)(BX*1), DX      \
    IMULQ   AX, DX               \
    ADDQ    DX, CX               \ // r2 = s * (s + b) + (sqrtResult << 32)
    \
    ADDQ    CX, BX               \
    XORQ    DX, DX               \
    CMPQ    BX, _tmp1            \
    SETHI   DL                   \
    SUBQ    DX, _sqrt_result     \ // sqrtResult += ((r2 + b > sqrtInput) ? -1 : 0)
    \ // NOTICE: the following branch does not seem to be able to be covered,
    \ //   i.e. it works without the code below.
    \ //   In case you find any issue, try de-commenting these.
    \
    \ // MOVQ    $0x100000000, DX
    \ // LEAQ    0(CX)(DX*1), BX
    \ // SUBQ    AX, _tmp1
    \ // XORQ    DX, DX
    \ // CMPQ    BX, _tmp1
    \ // SETCS   DL
    \ // ADDQ    DX, _sqrt_result  // sqrtResult += ((r2 + (1 << 32) < sqrtInput - s) ? 1 : 0)
    \
    \ /*** <END> VARIANT2_INTEGER_MATH_SQRT_FIXUP ***/

// func memhard2(cc *cache)
TEXT ·memhard2(SB), NOSPLIT, $48
    MOVQ    cc+0(FP), _cc
    LEAQ    0x200000(_cc), AX  // *cc.finalState

    MOVOU   0(AX), _tmpX0
    MOVOU   32(AX), _tmpX1
    PXOR    _tmpX0, _tmpX1
    MOVOU   _tmpX1, _a     // a = cc.finalState[0:2] ^ cc.finalState[4:6]

    MOVOU   16(AX), _tmpX0
    MOVOU   48(AX), _tmpX1
    PXOR    _tmpX0, _tmpX1
    MOVOU   _tmpX1, _b     // b = cc.finalState[2:4] ^ cc.finalState[6:8]

/*** <BEGIN> VARIANT2_INIT ***/
    MOVOU   64(AX), _tmpX0
    MOVOU   80(AX), _tmpX1
    PXOR    _tmpX0, _tmpX1
    MOVOU   _tmpX1, _e               // e = cc.finalState[8:10] ^ cc.finalState[10:12]
    MOVQ    96(AX), _division_result // divisionResult = cc.finalState[12]
    MOVQ    104(AX), _sqrt_result    // sqrtResult = cc.finalState[13]
/*** <END> VARIANT2_INIT ***/

    MOVQ    $0x80000, _i
ITER:
    MOVQ    _a, AX
    ANDQ    $0x1ffff0, AX      // addr = a[0] & 0x1ffff0
    LEAQ    0(_cc)(AX*1), _pad

    // single round of AES
    MOVOU   0(_pad), _c
    AESENC  _a, _c

/*** <BEGIN> VARIANT2_SHUFFLE_ADD ***/
    MOVQ    AX, BX
    XORQ    $0x10, BX
    LEAQ    0(_cc)(BX*1), BX
    MOVOU   0(BX), _tmpX0  // chunk0
    MOVQ    AX, CX
    XORQ    $0x20, CX
    LEAQ    0(_cc)(CX*1), CX
    MOVOU   0(CX), _tmpX1  // chunk1
    MOVQ    AX, DX
    XORQ    $0x30, DX
    LEAQ    0(_cc)(DX*1), DX
    MOVOU   0(DX), _tmpX2  // chunk2

    PADDQ   _e, _tmpX2
    PADDQ   _b, _tmpX0
    PADDQ   _a, _tmpX1

    MOVOU   _tmpX2, 0(BX)
    MOVOU   _tmpX0, 0(CX)
    MOVOU   _tmpX1, 0(DX)
/*** <END> VARIANT2_SHUFFLE_ADD ***/

    MOVOU   _b, _tmpX0
    PXOR    _c, _tmpX0
    MOVOU   _tmpX0, 0(_pad)    // cc.scratchpad[addr:addr+2] = b ^ c

    MOVQ    _c, _tmp0
    ANDQ    $0x1ffff0, _tmp0   // addr = c[0] & 0x1ffff0
    LEAQ    0(_cc)(_tmp0*1), _pad
    MOVOU   0(_pad), _d

/*** <BEGIN> VARIANT2_INTEGER_MATH_DIVISION_STEP ***/
    MOVQ    _d, BX             // d[0]
    MOVQ    _sqrt_result, CX
    SHLQ    $32, CX
    XORQ    _division_result, CX
    XORQ    CX, BX
    // TODO：replace with PSHUFHW?
    MOVQ    BX, _tmpX0
    MOVLHPS _tmpX0, _tmpX0
    MOVHLPS _tmpX0, _d

    MOVQ    _c, CX
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
    LEAQ    0(CX)(_division_result*1), _tmp1 // sqrtInput = c[0] + divisionResult
/*** <END> VARIANT2_INTEGER_MATH_DIVISION_STEP ***/
    V2_SQRT

/*** <BEGIN> VARIANT2_SHUFFLE_ADD ***/
    MOVQ    _tmp0, BX
    XORQ    $0x10, BX
    LEAQ    0(_cc)(BX*1), BX
    MOVOU   0(BX), _tmpX0  // chunk0
    MOVQ    _tmp0, CX
    XORQ    $0x20, CX
    LEAQ    0(_cc)(CX*1), CX
    MOVOU   0(CX), _tmpX1  // chunk1
    MOVQ    _tmp0, DX
    XORQ    $0x30, DX
    LEAQ    0(_cc)(DX*1), DX
    MOVOU   0(DX), _tmpX2  // chunk2

    PADDQ   _e, _tmpX2
    PADDQ   _b, _tmpX0
    PADDQ   _a, _tmpX1

    MOVOU   _tmpX2, 0(BX)
    MOVOU   _tmpX0, 0(CX)
    MOVOU   _tmpX1, 0(DX)
/*** <END> VARIANT2_SHUFFLE_ADD ***/
    MOVOU   _b, _e  // e = b

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

    MOVOU   _a, 0(_pad)  // cc.scratchpad[addr:addr+2] = a
    PXOR    _d, _a       // a ^= d
    MOVOU   _c, _b       // b = c

    DECQ    _i
    JNZ     ITER
    RET

// func v2SqrtAsm(sqrtInput uint64) (sqrtResult uint64)
TEXT ·v2SqrtAsm(SB), NOSPLIT, $0
    MOVQ    sqrtInput+0(FP), _tmp1
    V2_SQRT
    MOVQ    _sqrt_result, sqrtResult+8(FP)
    RET
