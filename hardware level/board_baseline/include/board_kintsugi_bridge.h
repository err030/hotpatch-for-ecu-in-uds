#ifndef BOARD_KINTSUGI_BRIDGE_H
#define BOARD_KINTSUGI_BRIDGE_H

#include <stdbool.h>
#include <stdint.h>

#include "uds_ecu.h"
#include "uds_link.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOARD_KINTSUGI_CONTROL_DID 0xF190U
#define BOARD_KINTSUGI_CONTROL_APPLY_SECURITY_HOTPATCH 0x01U
#define BOARD_KINTSUGI_CONTROL_RECEIVE_SECURITY_HOTPATCH 0x02U
#define BOARD_KINTSUGI_CONTROL_SCHEDULE_SECURITY_HOTPATCH 0x03U
#define BOARD_KINTSUGI_CONTROL_APPLY_SCHEDULED_HOTPATCH 0x04U

typedef struct {
    uds_ecu_t *ecu;
    bool initialized;
    bool hotpatch_loaded;
    bool hotpatch_scheduled;
    bool hotpatch_applied;
    uint32_t hotpatch_identifier;
    uint32_t receive_result;
    uint32_t schedule_result;
    uint32_t apply_result;
} board_kintsugi_bridge_t;

void board_kintsugi_bridge_init(
    board_kintsugi_bridge_t *bridge,
    uds_ecu_t *ecu
);

bool board_kintsugi_bridge_try_handle_control_frame(
    board_kintsugi_bridge_t *bridge,
    const uds_can_frame_t *request_frame,
    uint32_t response_id,
    uds_can_frame_t *response_frame_out
);

bool board_kintsugi_bridge_control_hook(
    const uds_can_frame_t *request_frame,
    uds_can_frame_t *response_frame_out,
    void *context
);

#ifdef __cplusplus
}
#endif

#endif
