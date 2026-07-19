#ifndef BOARD_RUNTIME_H
#define BOARD_RUNTIME_H

#include <stdbool.h>
#include <stdint.h>

#include "board_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UDS_BOARD_RUNTIME_IDLE = 0,
    UDS_BOARD_RUNTIME_FRAME_DROPPED,
    UDS_BOARD_RUNTIME_RESPONSE_SENT,
    UDS_BOARD_RUNTIME_SEND_FAILED,
} uds_board_runtime_poll_result_t;

typedef struct {
    uds_board_adapter_t *adapter;
    uds_board_can_port_t port;
    uint32_t ingress_frame_count;
    uint32_t response_sent_count;
    uint32_t blocked_frame_count;
    uint32_t endpoint_miss_count;
    uint32_t link_error_count;
} uds_board_runtime_t;

void uds_board_runtime_init(
    uds_board_runtime_t *runtime,
    uds_board_adapter_t *adapter,
    const uds_board_can_port_t *port,
    bool enable_default_trace_logging
);

uds_board_runtime_poll_result_t uds_board_runtime_poll_once(
    uds_board_runtime_t *runtime
);

#ifdef __cplusplus
}
#endif

#endif
