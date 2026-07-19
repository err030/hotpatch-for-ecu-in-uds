#include "hp_helper.h"


#pragma GCC optimize ("O0")
HOTPATCH_FUNCTION_START_NAKED(_do_syscall, 0xE, replacement, 0) {
	__asm__ volatile(
		".short 0xD302\n"
        ".short 0x6006\n"
        ".short 0xF04F\n"
        ".short 0x0697\n"
	);
}
#pragma GCC

/*
200000d8:	6006      	str	r6, [r0, #0]
200000da:	f04f 0697 	mov.w	r6, #151	@ 0x97
*/