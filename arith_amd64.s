#include "textflag.h"

// func byteAddMul(ret *[2]uint64, x, y uint64)
TEXT ·byteAddMul(SB), NOSPLIT, $0
    MOVQ ret+0(FP), CX
    MOVQ x+8(FP), AX
    MULQ y+16(FP)
    ADDQ DX, 0(CX)
    ADDQ AX, 8(CX)
    RET

// func mul128(low, high *uint64, x, y uint64)
TEXT ·mul128(SB), NOSPLIT, $0
    MOVQ low+0(FP), BX
    MOVQ high+8(FP), CX
    MOVQ x+16(FP), AX
    MULQ y+24(FP)
    MOVQ AX, BX
    MOVQ DX, CX
    RET
