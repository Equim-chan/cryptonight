// amd64 assembly implementation for memory hard step of variant 0, with SSE2 and AES-NI.
// We don't use extra stack at all, and of course no CALL is made.

#include "textflag.h"
#include "sum_defs_amd64.h"

// func memhard0(cc *cache)
TEXT ·memhard0(SB), NOSPLIT, $0
    MOVQ    cc+0(FP), _cc
    LEAQ    0x200000(_cc), AX  // *cc.finalState

    MOVOU   0(AX), _a
    PXOR    32(AX), _a         // a = cc.finalState[0:2] ^ cc.finalState[4:6]

    MOVOU   16(AX), _b
    PXOR    48(AX), _b         // b = cc.finalState[2:4] ^ cc.finalState[6:8]

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
