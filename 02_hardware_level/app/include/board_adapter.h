#ifndef BOARD_ADAPTER_H
#define BOARD_ADAPTER_H

#include <stdbool.h>
#include <stdint.h>

#include "uds_ecu.h"
#include "uds_gateway.h"
#include "uds_protocol.h"
#include "uds_tasks.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UDS_BOARD_PATH_DIRECT_ECU = 0,
    UDS_BOARD_PATH_GATEWAY_TO_ADJACENT_ECU,
} uds_board_path_mode_t;

typedef enum {
    UDS_BOARD_OUTCOME_NONE = 0,
    UDS_BOARD_OUTCOME_RESPONSE_READY,
    UDS_BOARD_OUTCOME_GATEWAY_BLOCKED,
    UDS_BOARD_OUTCOME_ENDPOINT_MISS,
    UDS_BOARD_OUTCOME_LINK_ERROR,
} uds_board_outcome_t;

typedef struct {
    bool valid;
    uds_board_path_mode_t path_mode;
    uds_board_outcome_t outcome;
    uds_link_status_t link_status;
    uds_can_frame_t ingress_frame;
    bool ingress_sid_valid;
    uint8_t ingress_sid;
    bool gateway_forwarded_request;
    bool gateway_forwarded_response;
    bool gateway_blocked_request;
    uint8_t gateway_blocked_sid;
    bool internal_request_valid;
    uds_can_frame_t internal_request_frame;
    bool ecu_request_accepted;
    uds_security_phase_t ecu_phase_before;
    uds_security_phase_t ecu_phase_after;
    bool internal_response_valid;
    uds_can_frame_t internal_response_frame;
    bool response_decoded;
    uds_response_t uds_response;
    bool egress_frame_valid;
    uds_can_frame_t egress_frame;
} uds_board_trace_t;

typedef void (*uds_board_trace_sink_t)(
    const uds_board_trace_t *trace,
    void *context
);

typedef bool (*uds_board_control_hook_t)(
    const uds_can_frame_t *ingress_frame,
    uds_can_frame_t *egress_frame_out,
    void *context
);

typedef bool (*uds_board_can_receive_fn)(
    uds_can_frame_t *frame_out,
    void *context
);

typedef bool (*uds_board_can_send_fn)(
    const uds_can_frame_t *frame,
    void *context
);

typedef struct {
    uds_board_can_receive_fn receive_frame;
    uds_board_can_send_fn send_frame;
    void *context;
} uds_board_can_port_t;

typedef struct {
    uds_board_path_mode_t path_mode;
    uds_gateway_task_t *gateway_task;
    uds_ecu_task_t *adjacent_ecu_task;
    uds_board_trace_t last_trace;
    uds_board_trace_sink_t trace_sink;
    void *trace_sink_context;
    uds_board_control_hook_t control_hook;
    void *control_hook_context;
} uds_board_adapter_t;

void uds_board_adapter_init_direct_ecu(
    uds_board_adapter_t *adapter,
    uds_ecu_task_t *ecu_task
);

void uds_board_adapter_init_gateway_path(
    uds_board_adapter_t *adapter,
    uds_gateway_task_t *gateway_task,
    uds_ecu_task_t *adjacent_ecu_task
);

void uds_board_adapter_set_trace_sink(
    uds_board_adapter_t *adapter,
    uds_board_trace_sink_t trace_sink,
    void *trace_sink_context
);

void uds_board_adapter_set_control_hook(
    uds_board_adapter_t *adapter,
    uds_board_control_hook_t control_hook,
    void *control_hook_context
);

bool uds_board_adapter_process_ingress_frame(
    uds_board_adapter_t *adapter,
    const uds_can_frame_t *ingress_frame,
    uds_can_frame_t *egress_frame_out
);

bool uds_board_adapter_pump_once(
    uds_board_adapter_t *adapter,
    const uds_board_can_port_t *port
);

const uds_board_trace_t *uds_board_adapter_last_trace(
    const uds_board_adapter_t *adapter
);

#ifdef __cplusplus
}
#endif

#endif
