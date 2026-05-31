#include "hp_helper.h"
#include "FreeRTOS.h"
#include "list.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_IP_Private.h"

#pragma GCC push_options
#pragma GCC optimize ("Os")
HOTPATCH_FUNCTION_START_NAKED(prvCheckOptions, 0x2, redirect, 0xA) {
    
	STORE_REGISTERS("r1, r2, r3");

	VAR_REG(pucLast, "ip", unsigned char *);
    VAR_REG(pxNetworkBuffer, "r1", NetworkBufferDescriptor_t *);
	VAR_REG(pxTCPPacket, "r3",  TCPPacket_t *);
	VAR_REG(pucPtr, "ip", const unsigned char *);

	pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
	/* A character pointer to iterate through the option data */
	pucPtr = pxTCPPacket->xTCPHeader.ucOptdata;
	pucLast = pucPtr + (((pxTCPPacket->xTCPHeader.ucTCPOffset >> 4) - 5) << 2);

    if( pucLast > ( pxNetworkBuffer->pucEthernetBuffer + pxNetworkBuffer->xDataLength ) )
    {
		SET_RETURN_VALUE(-1);
		RESTORE_REGISTERS("r1, r2, r3");
        __asm__ volatile("bx lr\n");
    }

	RESTORE_REGISTERS("r1, r2, r3");
	__asm__ volatile(
		"ldr 		r3, [r1, #24]\n"
		"ldrb.w 	ip, [r3, #46]\n"
		"mov.w 		ip, ip, lsr #4\n"
	);
    HOTPATCH_BRANCH_TO_ORIGINAL_CODE();
}
#pragma GCC pop_options

/*

20004150:	698b      	ldr	r3, [r1, #24]
20004152:	f893 c02e 	ldrb.w	ip, [r3, #46]	@ 0x2e
20004156:	ea4f 1c1c 	mov.w	ip, ip, lsr #4
2000415a:	3336      	adds	r3, #54	@ 0x36
2000415c:	f1ac 0c05 	sub.w	ip, ip, #5
20004160:	eb03 0c8c 	add.w	ip, r3, ip, lsl #2
20004164:	4563      	cmp	r3, ip
*/
/*
pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
pxTCPHeader = &pxTCPPacket->xTCPHeader;

 // A character pointer to iterate through the option data
pucPtr = pxTCPHeader->ucOptdata;
pucLast = pucPtr + (((pxTCPHeader->ucTCPOffset >> 4) - 5) << 2);
pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
 */