#ifndef UDS_GATEWAY_H
#define UDS_GATEWAY_H

#include <stdbool.h>
#include <stdint.h>

#include "uds_link.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UDS_GATEWAY_MODE_OPEN = 0,
    UDS_GATEWAY_MODE_RESTRICTED,
    UDS_GATEWAY_MODE_MISCONFIGURED,
} uds_gateway_mode_t;

typedef struct {
    uds_gateway_route_t route;
    uds_gateway_mode_t mode;
    bool last_frame_dropped;
    uint8_t last_blocked_sid;
} uds_gateway_t;

void uds_gateway_init(
    uds_gateway_t *gateway,
    const uds_gateway_route_t *route,
    uds_gateway_mode_t mode
);

bool uds_gateway_forward_frame(
    uds_gateway_t *gateway,
    const uds_can_frame_t *input_frame,
    uds_can_frame_t *output_frame
);

#ifdef __cplusplus
}
#endif

#endif
