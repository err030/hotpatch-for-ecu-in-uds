#include "FreeRTOS.h"
#include "list.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_IP_Private.h"

#include "hp_helper.h"

/*
    1. Patch "TLS_Init" to allocate 4 more bytes for the initialization flag, and set it to FALSE
    2. Patch "prvFreeContext" to set the flag to FALSE at the end of freeing
    3. Patch "TLS_Connect" to set the flag to TRUE at the end if the connection was successful
    4. Patch "TLS_Recv" to proceed only if the flag is TRUE
    5. Patch "TLS_Send" to proceed only if the flag is TRUE
    6. Patch "TLS_Cleanup" to free the context only if the flag is TRUE

*/


#pragma GCC push_options
#pragma GCC optimize ("Os")
HOTPATCH_FUNCTION_START_NAKED(xProcessReceivedTCPPacket, 0x8, redirect, 0x8) {
    VAR_REG(pxNetworkBuffer, "r0", NetworkBufferDescriptor_t *);

    if (pxNetworkBuffer->xDataLength < ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER) {
        SET_RETURN_VALUE(0);
        RESTORE_REGISTERS("r4 - r11, pc");
    }
    ORIGINAL_CODE();
	HOTPATCH_BRANCH_TO_ORIGINAL_CODE();
}
#pragma GCC pop_options