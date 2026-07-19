#include "hp_helper.h"

#include <mqtt_internal.h>
#pragma GCC push_options
#pragma GCC optimize ("Os")
HOTPATCH_FUNCTION_START_NAKED(packet_length_decode, 0x2, redirect, 0x8) {
	STORE_REGISTERS("r1 - r6");

	VAR_REG(buf, "r0", struct buf_ctx *);
	VAR_REG(length, "r1", uint32_t *);
	
	uint8_t shift = 0U;
	uint8_t bytes = 0U;

	*length = 0U;
	do {
		// + if (bytes >= MQTT_MAX_LENGTH_BYTES)
		if (bytes >= MQTT_MAX_LENGTH_BYTES) {
			//return -EINVAL;
			SET_RETURN_VALUE(-EINVAL);
			RESTORE_REGISTERS("r1 - r6");
			RESTORE_REGISTERS("R4, PC");
		}

		if (buf->cur >= buf->end) {
			//return -EAGAIN
			SET_RETURN_VALUE(-EAGAIN);
			RESTORE_REGISTERS("r1 - r6");
			RESTORE_REGISTERS("R4, PC");
		}

		*length += ((uint32_t)*(buf->cur) & MQTT_LENGTH_VALUE_MASK)
								<< shift;
		shift += MQTT_LENGTH_SHIFT;
		bytes++;
	} while ((*(buf->cur++) & MQTT_LENGTH_CONTINUATION_BIT) != 0U);

	if (*length > MQTT_MAX_PAYLOAD_SIZE) {
		SET_RETURN_VALUE(-EINVAL);
		RESTORE_REGISTERS("r1 - r6");
		RESTORE_REGISTERS("R4, PC");
	}

	SET_RETURN_VALUE(0);
	RESTORE_REGISTERS("r1 - r6");
	RESTORE_REGISTERS("R4, PC");
}
#pragma GCC