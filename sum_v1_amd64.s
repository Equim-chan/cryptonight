// amd64 assembly implementation for memory hard step of variant 1, with SSE2 and AES-NI.
// We don't use extra stack at all, and of course no CALL is made.

#include "textflag.h"
#include "sum_defs_amd64.h"

// func memhard1(cc *cache, tweak uint64)
TEXT ·memhard1(SB), NOSPLIT, $0
    MOVQ    cc+0(FP), _cc
    LEAQ    0x200000(_cc), AX  // *cc.finalState

    MOVOU   0(AX), _tmpX0
    MOVOU   32(AX), _a
    PXOR    _tmpX0, _a         // a = cc.finalState[0:2] ^ cc.finalState[4:6]

    MOVOU   16(AX), _tmpX0
    MOVOU   48(AX), _b
    PXOR    _tmpX0, _b         // b = cc.finalState[2:4] ^ cc.finalState[6:8]

    // <BEGIN> VARIANT1_INIT
    MOVQ    tweak+8(FP), _tweak
    // <END> VARIANT1_INIT
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

    // <BEGIN> VARIANT1_1
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
    // <END> VARIANT1_1

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
    // <BEGIN> VARIANT1_2
    XORQ    _tweak, 8(_pad)
    // <END> VARIANT1_2
    PXOR    _d, _a  // a ^= d
    MOVOU   _c, _b  // b = c

    DECQ    _i
    JNZ     ITER
    RET
