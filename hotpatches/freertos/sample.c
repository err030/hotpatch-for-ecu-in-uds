#include "hp_helper.h"

HOTPATCH_FUNCTION_START_NAKED(target_ram_function, 0x0, redirect, 0x8) {
    __asm__ volatile(
		"subs 	r4, r0, r1	\n\t" \
		"adds	r2, r4, #1	\n\t" \
		"subs 	r4, r0, r3  \n\t" \
		"add	r1, r6		\n\t" \
		"adds 	r0, r6, r5	\n\t" \
	);
	HOTPATCH_BRANCH_TO_ORIGINAL_CODE();
}


/*
200000d8:	6006      	str	r6, [r0, #0]
200000da:	f04f 0697 	mov.w	r6, #151	@ 0x97
*/