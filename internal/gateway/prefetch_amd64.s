#include "textflag.h"

// func prefetch(b []byte)
TEXT ·prefetch(SB), NOSPLIT, $0-24
	MOVQ b_base+0(FP), AX
	PREFETCHT0 (AX)
	RET
