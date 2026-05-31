#include "hp_helper.h"

HOTPATCH_FUNCTION_START_NAKED(z_shell_spaces_trim, 0xE, redirect, 0x8) {
    __asm__ volatile(
		"subs 	r4, r0, r1	\n\t" \
		"adds	r2, r4, #1	\n\t" \
		"subs 	r4, r0, r3  \n\t" \
		"add	r1, r6		\n\t" \
		"adds 	r0, r6, r5	\n\t" \
	);
	HOTPATCH_BRANCH_TO_ORIGINAL_CODE();
}
