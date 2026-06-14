#ifndef UDS_ECU_H
#define UDS_ECU_H

#include <stdint.h>

#include "uds_dispatcher.h"
#include "uds_link.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uds_ecu_link_t link;
    uds_dispatcher_t dispatcher;
} uds_ecu_t;

void uds_ecu_init_strict(
    uds_ecu_t *ecu,
    uint32_t request_id,
    uint32_t response_id
);

void uds_ecu_init_vulnerable(
    uds_ecu_t *ecu,
    uint32_t request_id,
    uint32_t response_id
);

void uds_ecu_apply_security_access_hotpatch(uds_ecu_t *ecu);

bool uds_ecu_accepts_request_frame(
    const uds_ecu_t *ecu,
    const uds_can_frame_t *frame
);

uds_link_status_t uds_ecu_handle_request_frame(
    uds_ecu_t *ecu,
    const uds_can_frame_t *request_frame,
    uds_can_frame_t *response_frame_out
);

#ifdef __cplusplus
}
#endif

#endif
