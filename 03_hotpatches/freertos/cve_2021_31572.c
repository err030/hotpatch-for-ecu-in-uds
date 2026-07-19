#include "hp_helper.h"
#include "FreeRTOS.h"
#include "stream_buffer.h"

/*
if( xBufferSizeBytes < ( xBufferSizeBytes + 1 + sizeof( StreamBuffer_t ) ) )
{
	xBufferSizeBytes++;
	pucAllocatedMemory = ( uint8_t * ) pvPortMalloc( xBufferSizeBytes + sizeof( StreamBuffer_t ) );
}
else
{
	pucAllocatedMemory = NULL;
}
*/

struct StreamBuffer_t               /*lint !e9058 Style convention uses tag. */
{
    volatile size_t xTail;                       /* Index to the next item to read within the buffer. */
    volatile size_t xHead;                       /* Index to the next item to write within the buffer. */
    size_t xLength;                              /* The length of the buffer pointed to by pucBuffer. */
    size_t xTriggerLevelBytes;                   /* The number of bytes that must be in the stream buffer before a task that is waiting for data is unblocked. */
    volatile uint32_t xTaskWaitingToReceive; /* Holds the handle of a task waiting for data, or NULL if no tasks are waiting. */
    volatile uint32_t xTaskWaitingToSend;    /* Holds the handle of a task waiting to send data to a message buffer that is full. */
    uint8_t * pucBuffer;                         /* Points to the buffer itself - that is - the RAM that stores the data passed through the buffer. */
    uint8_t ucFlags;

    #if ( configUSE_TRACE_FACILITY == 1 )
        UBaseType_t uxStreamBufferNumber; /* Used for tracing purposes. */
    #endif
} ;

HOTPATCH_FUNCTION_START_NAKED(xStreamBufferGenericCreate, 0x2, redirect, 0xC) {

	VAR_REG(pucAllocatedMemory, "r0", uint8_t *);

	VAR_REG(xBufferSizeBytes, "r0", uint32_t);
	VAR_REG(xTriggerLevelBytes, "r1", uint32_t);
	VAR_REG(xIsMessageBuffer, "r2", uint32_t);

	// function related storage
	VAR_REG(str_xBufferSizeBytes, "r5", uint32_t);
	VAR_REG(str_xTriggerLevelBytes, "r7", uint32_t);
	VAR_REG(str_xIsMessageBuffer, "r6", uint32_t);

	str_xBufferSizeBytes = xBufferSizeBytes;
	str_xTriggerLevelBytes = xTriggerLevelBytes;
	str_xIsMessageBuffer = xIsMessageBuffer;

	// add comparison
	if (str_xBufferSizeBytes < (str_xBufferSizeBytes + 1 + sizeof(struct StreamBuffer_t))) {
		str_xBufferSizeBytes++;
		pucAllocatedMemory = ( uint8_t * ) pvPortMalloc( str_xBufferSizeBytes + sizeof( struct StreamBuffer_t ) );
	} else {
		pucAllocatedMemory = NULL;
	}

	HOTPATCH_BRANCH_TO_ORIGINAL_CODE();

	CALL_FUNC_DEF(pvPortMalloc);
}