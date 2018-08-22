#include "textflag.h"

// func v2ShuffleAsm(basePtr *uint64, offset uint64)
TEXT ·v2ShuffleAsm(SB), NOSPLIT, $0
    MOVQ    basePtr+0(FP), CX
    MOVQ    offset+8(FP), DX
    // since we use []uint64 instead of []uint8 as scratchpad, the offset applies too
    SHLQ    $3, DX
    MOVQ    DX, R8
    MOVQ    DX, AX
    XORQ    $48, DX
    XORQ    $16, R8
    XORQ    $32, AX
    ADDQ    CX, R8
    ADDQ    CX, AX
    ADDQ    DX, CX
    VMOVDQA     (R8), X1
    VMOVDQA     (AX), X0
    VPSHUFD     $141, (CX), X2
    VPSHUFLW    $216, X2, X2
    VMOVAPS     X2, (R8)
    VPSHUFD     $54, X1, X1
    VPSHUFD     $216, X0, X0
    VPSHUFLW    $54, X1, X1
    VPSHUFLW    $141, X0, X0
    VMOVAPS     X1, (AX)
    VMOVAPS     X0, (CX)
    RET
