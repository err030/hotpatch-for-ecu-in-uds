#include "hp_helper.h"
#include "pico_frame.h"
#include "pico_icmp6.h"

#pragma GCC push_options
#pragma GCC optimize ("Os")
HOTPATCH_FUNCTION_START_NAKED(pico_icmp6_send_echoreply, 0x2, redirect, 0xC) {
    VAR_REG(echo, "r0", struct pico_frame *);

    if (echo->transport_len < PICO_ICMP6HDR_ECHO_REQUEST_SIZE) {
        SET_RETURN_VALUE(2);
        RESTORE_REGISTERS("r4, r7, pc");
        
    }
    ORIGINAL_CODE();
	HOTPATCH_BRANCH_TO_ORIGINAL_CODE();
}
#pragma GCC pop_options