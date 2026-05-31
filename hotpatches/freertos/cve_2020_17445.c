#include "hp_helper.h"
#include "pico_frame.h"
#include "pico_icmp6.h"

#pragma GCC push_options
#pragma GCC optimize ("Os")
HOTPATCH_FUNCTION_START_NAKED(pico_ipv6_process_destopt, 0x40, redirect, 8) {
    STORE_REGISTERS("r2, r3");
    VAR_REG(optlen, "r3", uint8_t);
    VAR_MEMORY_REG_PTR(len, "r7", 19, uint8_t);
    
    if ((optlen > *len) || (optlen == 0)) {
        SET_RETURN_VALUE(2);
        RESTORE_REGISTERS("r2, r3");
        SKIP_STACK(24);
        RESTORE_REGISTERS("r7, pc");
    }
    RESTORE_REGISTERS("r2, r3");
    ORIGINAL_CODE();
    HOTPATCH_BRANCH_TO_ORIGINAL_CODE();
}
#pragma GCC pop_options