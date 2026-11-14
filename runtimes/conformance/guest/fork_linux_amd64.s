#include "textflag.h"
TEXT ·forkHold(SB),NOSPLIT,$0-16
 MOVQ $57, AX
 SYSCALL
 CMPQ AX, $0
 JE child
 CMPQ AX, $0
 JL failed
 MOVQ AX, pid+0(FP)
 MOVQ $0, errno+8(FP)
 RET
failed:
 NEGQ AX
 MOVQ $-1, pid+0(FP)
 MOVQ AX, errno+8(FP)
 RET
child:
 MOVQ $34, AX
 SYSCALL
 JMP child
