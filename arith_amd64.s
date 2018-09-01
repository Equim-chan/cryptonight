#include "textflag.h"

// func mul128(x, y uint64) (lo, hi uint64)
TEXT ·mul128(SB), NOSPLIT, $0
    MOVQ x+0(FP), AX
    MULQ y+8(FP)
    MOVQ AX, lo+16(FP)
    MOVQ DX, hi+24(FP)
    RET
