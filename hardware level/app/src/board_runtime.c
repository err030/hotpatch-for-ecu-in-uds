#include "board_runtime.h"

#include <string.h>

#include "board_log.h"
#include "board_trace_log.h"

void uds_board_runtime_init(
    uds_board_runtime_t *runtime,
    uds_board_adapter_t *adapter,
    const uds_board_can_port_t *port,
    bool enable_default_trace_logging
)
{
    if (runtime == NULL) {
        return;
    }

    memset(runtime, 0, sizeof(*runtime));
    runtime->adapter = adapter;
    if (port != NULL) {
        runtime->port = *port;
    }

    if (enable_default_trace_logging && adapter != NULL) {
        uds_board_adapter_set_trace_sink(adapter, board_trace_log_sink, NULL);
    }
}

uds_board_runtime_poll_result_t uds_board_runtime_poll_once(
    uds_board_runtime_t *runtime
)
{
    uds_can_frame_t ingress_frame;
    uds_can_frame_t egress_frame;
    const uds_board_trace_t *trace;
    bool handled;

    if (runtime == NULL ||
        runtime->adapter == NULL ||
        runtime->port.receive_frame == NULL ||
        runtime->port.send_frame == NULL) {
        return UDS_BOARD_RUNTIME_IDLE;
    }

    if (!runtime->port.receive_frame(&ingress_frame, runtime->port.context)) {
        return UDS_BOARD_RUNTIME_IDLE;
    }

    runtime->ingress_frame_count += 1U;
    handled = uds_board_adapter_process_ingress_frame(
        runtime->adapter,
        &ingress_frame,
        &egress_frame
    );
    trace = uds_board_adapter_last_trace(runtime->adapter);

    if (trace == NULL || !trace->valid) {
        return UDS_BOARD_RUNTIME_FRAME_DROPPED;
    }

    switch (trace->outcome) {
    case UDS_BOARD_OUTCOME_GATEWAY_BLOCKED:
        runtime->blocked_frame_count += 1U;
        return UDS_BOARD_RUNTIME_FRAME_DROPPED;

    case UDS_BOARD_OUTCOME_ENDPOINT_MISS:
        runtime->endpoint_miss_count += 1U;
        return UDS_BOARD_RUNTIME_FRAME_DROPPED;

    case UDS_BOARD_OUTCOME_LINK_ERROR:
        runtime->link_error_count += 1U;
        return UDS_BOARD_RUNTIME_FRAME_DROPPED;

    case UDS_BOARD_OUTCOME_RESPONSE_READY:
        break;

    case UDS_BOARD_OUTCOME_NONE:
    default:
        return UDS_BOARD_RUNTIME_FRAME_DROPPED;
    }

    if (!handled) {
        runtime->link_error_count += 1U;
        return UDS_BOARD_RUNTIME_FRAME_DROPPED;
    }

    if (!runtime->port.send_frame(&egress_frame, runtime->port.context)) {
        runtime->link_error_count += 1U;
        board_log_printf(
            "[UDS][PORT] failed to send response can_id=0x%03lX\n",
            (unsigned long)egress_frame.arbitration_id
        );
        return UDS_BOARD_RUNTIME_SEND_FAILED;
    }

    runtime->response_sent_count += 1U;
    return UDS_BOARD_RUNTIME_RESPONSE_SENT;
}
