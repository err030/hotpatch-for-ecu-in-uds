#include "hp_helper.h"
#include <zephyr/net/coap.h>

#pragma GCC push_options
#pragma GCC optimize ("O0")

HOTPATCH_FUNCTION_START_NAKED(parse_option, 0xB0, redirect, 0x18) {

	VAR_REG(opt_delta, "r7", uint16_t*);
	VAR_REG(opt_len, "sl", uint16_t*);
	
	VAR_REG(a, "r3", uint32_t);
	VAR_REG(b, "r2", uint32_t);
	VAR_REG(c, "ip", uint32_t);

	a = *opt_delta;
	b = READ_STACK(uint16_t, 20);
	
	c = (a + b) & 0xFFFF;
	
	*opt_delta = c;
	
	if (c < a) {
		SET_RETURN_VALUE(-EINVAL);
        __asm__ volatile("add sp, #28\n");
		RESTORE_REGISTERS("r4, r5, r6, r7, r8, r9, sl, fp, pc");

	}

	//
	a = *opt_len;
	b = READ_STACK(uint16_t, 22);

	c = (a + b) & 0xFFFF;

	*opt_len = c;

	if (c < a) {
		SET_RETURN_VALUE(-EINVAL);
        __asm__ volatile("add sp, #28\n");
		RESTORE_REGISTERS("r4, r5, r6, r7, r8, r9, sl, fp, pc");
	}

	HOTPATCH_BRANCH_TO_ORIGINAL_CODE();
}
#pragma GCC
#pragma GCC