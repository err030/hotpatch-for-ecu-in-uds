#include "mbedtls/ecp.h"
#include "hp_helper.h"

#pragma GCC push_options
#pragma GCC optimize ("Os")
HOTPATCH_FUNCTION_START_NAKED(mbedtls_ecp_check_pubkey, 4, redirect, 8) {
    STORE_REGISTERS("r3");
    VAR_REG(grp, "r0", const mbedtls_ecp_group *);

    if (grp->id == MBEDTLS_ECP_DP_SECP224K1) {
        SET_RETURN_VALUE(MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE);
        RESTORE_REGISTERS("r3-r8, pc");
    }
    RESTORE_REGISTERS("r3");
	ORIGINAL_CODE();
    HOTPATCH_BRANCH_TO_ORIGINAL_CODE();
}
#pragma GCC pop_options