#include "textflag.h"

// func byteMul(product *[2]uint64, x, y uint64)
TEXT ·byteMul(SB), NOSPLIT, $0
    MOVQ product+0(FP), CX
    MOVQ x+8(FP), AX
    MULQ y+16(FP)
    MOVQ DX, 0(CX)
    MOVQ AX, 8(CX)
    RET
