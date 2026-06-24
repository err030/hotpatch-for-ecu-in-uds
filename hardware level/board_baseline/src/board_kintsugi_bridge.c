#include "board_kintsugi_bridge.h"

#include <string.h>

#include "board_baseline_config.h"
#include "hp_manager.h"
#include "uds_protocol.h"

typedef struct {
    struct hp_header header;
    uint8_t code[4];
} board_kintsugi_patch_blob_t;

static uint32_t __attribute__((section(".ramfunc"), naked, noinline, used))
board_kintsugi_security_hotpatch_gate(void)
{
    __asm__ volatile(
        "movs r0, #0\n"
        "nop\n"
        "nop\n"
        "bx lr\n"
    );
}

static bool board_kintsugi_gate_active(void)
{
    return board_kintsugi_security_hotpatch_gate() != 0U;
}

static void board_kintsugi_build_gate_patch(board_kintsugi_patch_blob_t *blob)
{
    memset(blob, 0, sizeof(*blob));
    blob->header.type = HP_TYPE_REDIRECT;
    blob->header.target_address =
        ((uint32_t)board_kintsugi_security_hotpatch_gate) & ~1UL;
    blob->header.code_size = sizeof(blob->code);

    /* Thumb: movs r0,#1; bx lr */
    blob->code[0] = 0x01U;
    blob->code[1] = 0x20U;
    blob->code[2] = 0x70U;
    blob->code[3] = 0x47U;
}

static void board_kintsugi_bridge_poll(board_kintsugi_bridge_t *bridge)
{
    if (bridge == NULL || bridge->ecu == NULL || bridge->hotpatch_applied) {
        return;
    }
    if (!board_kintsugi_gate_active()) {
        return;
    }

    uds_ecu_apply_security_access_hotpatch(bridge->ecu);
    bridge->hotpatch_applied = true;
}

static bool board_kintsugi_receive_security_hotpatch(board_kintsugi_bridge_t *bridge)
{
    board_kintsugi_patch_blob_t blob;
    uint32_t identifier = 0U;

    if (bridge == NULL || bridge->ecu == NULL || !bridge->initialized) {
        return false;
    }
    if (bridge->hotpatch_loaded) {
        return true;
    }

    board_kintsugi_build_gate_patch(&blob);
    bridge->receive_result = (uint32_t)hp_manager_receive_hotpatch(
        (const uint8_t *)&blob,
        sizeof(blob),
        &identifier
    );
    if (bridge->receive_result != HP_MANAGER_SUCCESS) {
        return false;
    }

    bridge->hotpatch_identifier = identifier;
    bridge->hotpatch_loaded = true;
    bridge->hotpatch_scheduled = false;
    bridge->hotpatch_applied = false;
    return true;
}

static bool board_kintsugi_schedule_security_hotpatch(board_kintsugi_bridge_t *bridge)
{
    if (bridge == NULL || bridge->ecu == NULL || !bridge->initialized) {
        return false;
    }
    if (bridge->hotpatch_applied || bridge->hotpatch_scheduled) {
        return true;
    }
    if (!bridge->hotpatch_loaded) {
        return false;
    }

    bridge->schedule_result =
        (uint32_t)hp_manager_schedule_hotpatch(bridge->hotpatch_identifier);
    if (bridge->schedule_result != HP_MANAGER_SUCCESS) {
        return false;
    }

    bridge->hotpatch_scheduled = true;
    return true;
}

static bool board_kintsugi_apply_scheduled_security_hotpatch(board_kintsugi_bridge_t *bridge)
{
    if (bridge == NULL || bridge->ecu == NULL || !bridge->initialized) {
        return false;
    }
    if (bridge->hotpatch_applied) {
        return true;
    }
    if (!bridge->hotpatch_scheduled) {
        return false;
    }

    bridge->apply_result =
        (uint32_t)hp_manager_apply_scheduled_hotpatch(bridge->hotpatch_identifier);
    if (bridge->apply_result != HP_MANAGER_SUCCESS) {
        return false;
    }

    board_kintsugi_bridge_poll(bridge);
    return bridge->hotpatch_applied;
}

static bool board_kintsugi_apply_security_hotpatch(board_kintsugi_bridge_t *bridge)
{
    if (!board_kintsugi_receive_security_hotpatch(bridge)) {
        return false;
    }
    if (!board_kintsugi_schedule_security_hotpatch(bridge)) {
        return false;
    }
    return board_kintsugi_apply_scheduled_security_hotpatch(bridge);
}

static bool board_kintsugi_decode_control_request(
    const uds_can_frame_t *request_frame,
    uint8_t *command_out
)
{
    uint8_t payload[UDS_CAN_SINGLE_FRAME_MAX_PAYLOAD];
    uint8_t payload_length = 0U;
    uint16_t did;

    if (request_frame == NULL || command_out == NULL) {
        return false;
    }
    if (uds_can_unpack_single_frame_payload(
            request_frame,
            payload,
            &payload_length) != UDS_LINK_STATUS_OK) {
        return false;
    }
    if (payload_length != 4U || payload[0] != SID_WRITE_DATA_BY_IDENTIFIER) {
        return false;
    }

    did = (uint16_t)(((uint16_t)payload[1] << 8) | payload[2]);
    if (did != BOARD_KINTSUGI_CONTROL_DID) {
        return false;
    }

    *command_out = payload[3];
    return true;
}

static bool board_kintsugi_build_control_response(
    uint32_t response_id,
    uint8_t nrc,
    uds_can_frame_t *response_frame_out
)
{
    uint8_t payload[3];

    if (response_frame_out == NULL) {
        return false;
    }

    if (nrc == 0U) {
        payload[0] = uds_positive_response_sid(SID_WRITE_DATA_BY_IDENTIFIER);
        payload[1] = (uint8_t)(BOARD_KINTSUGI_CONTROL_DID >> 8);
        payload[2] = (uint8_t)(BOARD_KINTSUGI_CONTROL_DID & 0xFFU);
        return uds_can_pack_single_frame_payload(
            response_frame_out,
            response_id,
            payload,
            3U
        ) == UDS_LINK_STATUS_OK;
    }

    payload[0] = NEGATIVE_RESPONSE_SID;
    payload[1] = SID_WRITE_DATA_BY_IDENTIFIER;
    payload[2] = nrc;
    return uds_can_pack_single_frame_payload(
        response_frame_out,
        response_id,
        payload,
        3U
    ) == UDS_LINK_STATUS_OK;
}

void board_kintsugi_bridge_init(
    board_kintsugi_bridge_t *bridge,
    uds_ecu_t *ecu
)
{
    if (bridge == NULL) {
        return;
    }

    memset(bridge, 0, sizeof(*bridge));
    bridge->ecu = ecu;
    hp_manager_init();
    bridge->initialized = true;
}

bool board_kintsugi_bridge_try_handle_control_frame(
    board_kintsugi_bridge_t *bridge,
    const uds_can_frame_t *request_frame,
    uint32_t response_id,
    uds_can_frame_t *response_frame_out
)
{
    uint8_t command;
    uint8_t nrc = NRC_REQUEST_OUT_OF_RANGE;

    if (!board_kintsugi_decode_control_request(request_frame, &command)) {
        return false;
    }

    if (command == BOARD_KINTSUGI_CONTROL_APPLY_SECURITY_HOTPATCH) {
        nrc = board_kintsugi_apply_security_hotpatch(bridge) ?
            0U :
            NRC_CONDITIONS_NOT_CORRECT;
    } else if (command == BOARD_KINTSUGI_CONTROL_RECEIVE_SECURITY_HOTPATCH) {
        nrc = board_kintsugi_receive_security_hotpatch(bridge) ?
            0U :
            NRC_CONDITIONS_NOT_CORRECT;
    } else if (command == BOARD_KINTSUGI_CONTROL_SCHEDULE_SECURITY_HOTPATCH) {
        nrc = board_kintsugi_schedule_security_hotpatch(bridge) ?
            0U :
            NRC_CONDITIONS_NOT_CORRECT;
    } else if (command == BOARD_KINTSUGI_CONTROL_APPLY_SCHEDULED_HOTPATCH) {
        nrc = board_kintsugi_apply_scheduled_security_hotpatch(bridge) ?
            0U :
            NRC_CONDITIONS_NOT_CORRECT;
    }

    (void)board_kintsugi_build_control_response(
        response_id,
        nrc,
        response_frame_out
    );
    return true;
}

bool board_kintsugi_bridge_control_hook(
    const uds_can_frame_t *request_frame,
    uds_can_frame_t *response_frame_out,
    void *context
)
{
    return board_kintsugi_bridge_try_handle_control_frame(
        (board_kintsugi_bridge_t *)context,
        request_frame,
        BOARD_UDS_EXTERNAL_RESPONSE_CAN_ID,
        response_frame_out
    );
}
