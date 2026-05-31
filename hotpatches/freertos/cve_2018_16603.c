#include "FreeRTOS.h"
#include "list.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_IP_Private.h"

#include "hp_helper.h"

#pragma GCC push_options
#pragma GCC optimize ("Os")
HOTPATCH_FUNCTION_START_NAKED(xProcessReceivedTCPPacket, 0x4, redirect, 0x6) {
    VAR_REG(pxNetworkBuffer, "r0", NetworkBufferDescriptor_t *);

    if (pxNetworkBuffer->xDataLength < ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER) {
        SET_RETURN_VALUE(-1);
        RESTORE_REGISTERS("r4 - r11, pc");
    }
    
    __asm__ volatile(
        "ldr    r6, [r0, #24]\n"
        "ldrh   r3, [r6, #34]\n"
        "ldrh   r1, [r6, #36]\n"
        "ldr    r2, [r6, #26]\n"
    );
	HOTPATCH_BRANCH_TO_ORIGINAL_CODE();
}
#pragma GCC pop_options

/*
200041c8 <xProcessReceivedTCPPacket>:
200041c8:	e92d 4ff0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
200041cc:	6986      	ldr	r6, [r0, #24]
200041ce:	8c73      	ldrh	r3, [r6, #34]	@ 0x22
200041d0:	8cb1      	ldrh	r1, [r6, #36]	@ 0x24
200041d2:	f8d6 201a 	ldr.w	r2, [r6, #26]
200041d6:	f896 702f 	ldrb.w	r7, [r6, #47]	@ 0x2f
*/

/*
FreeRTOS_Socket_t *pxSocket;
TCPPacket_t * pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
uint16_t ucTCPFlags = pxTCPPacket->xTCPHeader.ucTCPFlags;
uint32_t ulLocalIP = FreeRTOS_htonl( pxTCPPacket->xIPHeader.ulDestinationIPAddress );
uint16_t xLocalPort = FreeRTOS_htons( pxTCPPacket->xTCPHeader.usDestinationPort );
uint32_t ulRemoteIP = FreeRTOS_htonl( pxTCPPacket->xIPHeader.ulSourceIPAddress );
uint16_t xRemotePort = FreeRTOS_htons( pxTCPPacket->xTCPHeader.usSourcePort );
BaseType_t xResult = pdPASS;

	pxSocket = ( FreeRTOS_Socket_t * ) pxTCPSocketLookup( ulLocalIP, xLocalPort, ulRemoteIP, xRemotePort );

	if( ( pxSocket == NULL ) || ( prvTCPSocketIsActive( ( UBaseType_t ) pxSocket->u.xTCP.ucTCPState ) == pdFALSE ) )
	{
*/