#include "board_adapter.h"

#include <string.h>

static void uds_board_trace_reset(
    uds_board_trace_t *trace,
    uds_board_path_mode_t path_mode,
    const uds_can_frame_t *ingress_frame
)
{
    memset(trace, 0, sizeof(*trace));
    trace->valid = true;
    trace->path_mode = path_mode;
    trace->outcome = UDS_BOARD_OUTCOME_NONE;
    trace->link_status = UDS_LINK_STATUS_OK;
    if (ingress_frame != NULL) {
        trace->ingress_frame = *ingress_frame;
        trace->ingress_sid_valid = uds_can_extract_service_id(
            ingress_frame,
            &trace->ingress_sid
        );
    }
}

static uds_ecu_t *uds_board_task_ecu(const uds_ecu_task_t *task)
{
    if (task == NULL) {
        return NULL;
    }

    return task->ecu;
}

static void uds_board_trace_capture_phases(
    uds_board_trace_t *trace,
    const uds_ecu_task_t *ecu_task,
    bool before
)
{
    uds_ecu_t *ecu = uds_board_task_ecu(ecu_task);
    uds_security_phase_t phase;

    if (trace == NULL || ecu == NULL) {
        return;
    }

    phase = uds_dispatcher_security_phase(&ecu->dispatcher);
    if (before) {
        trace->ecu_phase_before = phase;
    } else {
        trace->ecu_phase_after = phase;
    }
}

static void uds_board_trace_decode_response(
    uds_board_trace_t *trace,
    const uds_can_frame_t *frame
)
{
    uint8_t payload[UDS_CAN_SINGLE_FRAME_MAX_PAYLOAD];
    uint8_t payload_length = 0U;

    if (trace == NULL || frame == NULL) {
        return;
    }

    if (uds_can_unpack_single_frame_payload(frame, payload, &payload_length) !=
        UDS_LINK_STATUS_OK) {
        return;
    }

    trace->response_decoded = uds_response_from_payload(
        &trace->uds_response,
        payload,
        payload_length
    );
}

static void uds_board_trace_finish(
    uds_board_adapter_t *adapter
)
{
    if (adapter == NULL || adapter->trace_sink == NULL) {
        return;
    }

    adapter->trace_sink(&adapter->last_trace, adapter->trace_sink_context);
}

void uds_board_adapter_init_direct_ecu(
    uds_board_adapter_t *adapter,
    uds_ecu_task_t *ecu_task
)
{
    if (adapter == NULL) {
        return;
    }

    memset(adapter, 0, sizeof(*adapter));
    adapter->path_mode = UDS_BOARD_PATH_DIRECT_ECU;
    adapter->adjacent_ecu_task = ecu_task;
}

void uds_board_adapter_init_gateway_path(
    uds_board_adapter_t *adapter,
    uds_gateway_task_t *gateway_task,
    uds_ecu_task_t *adjacent_ecu_task
)
{
    if (adapter == NULL) {
        return;
    }

    memset(adapter, 0, sizeof(*adapter));
    adapter->path_mode = UDS_BOARD_PATH_GATEWAY_TO_ADJACENT_ECU;
    adapter->gateway_task = gateway_task;
    adapter->adjacent_ecu_task = adjacent_ecu_task;
}

void uds_board_adapter_set_trace_sink(
    uds_board_adapter_t *adapter,
    uds_board_trace_sink_t trace_sink,
    void *trace_sink_context
)
{
    if (adapter == NULL) {
        return;
    }

    adapter->trace_sink = trace_sink;
    adapter->trace_sink_context = trace_sink_context;
}

void uds_board_adapter_set_control_hook(
    uds_board_adapter_t *adapter,
    uds_board_control_hook_t control_hook,
    void *control_hook_context
)
{
    if (adapter == NULL) {
        return;
    }

    adapter->control_hook = control_hook;
    adapter->control_hook_context = control_hook_context;
}

static bool uds_board_adapter_process_direct(
    uds_board_adapter_t *adapter,
    const uds_can_frame_t *ingress_frame,
    uds_can_frame_t *egress_frame_out
)
{
    uds_ecu_t *ecu;

    ecu = uds_board_task_ecu(adapter->adjacent_ecu_task);
    if (ecu == NULL) {
        adapter->last_trace.link_status = UDS_LINK_STATUS_INVALID_ARG;
        adapter->last_trace.outcome = UDS_BOARD_OUTCOME_LINK_ERROR;
        uds_board_trace_finish(adapter);
        return false;
    }

    adapter->last_trace.ecu_request_accepted = uds_ecu_accepts_request_frame(
        ecu,
        ingress_frame
    );
    if (!adapter->last_trace.ecu_request_accepted) {
        adapter->last_trace.link_status = UDS_LINK_STATUS_NOT_FOR_ENDPOINT;
        adapter->last_trace.outcome = UDS_BOARD_OUTCOME_ENDPOINT_MISS;
        uds_board_trace_finish(adapter);
        return false;
    }

    uds_board_trace_capture_phases(&adapter->last_trace, adapter->adjacent_ecu_task, true);
    adapter->last_trace.link_status = uds_ecu_task_process_frame(
        adapter->adjacent_ecu_task,
        ingress_frame,
        &adapter->last_trace.egress_frame
    );
    uds_board_trace_capture_phases(&adapter->last_trace, adapter->adjacent_ecu_task, false);

    if (adapter->last_trace.link_status != UDS_LINK_STATUS_OK) {
        adapter->last_trace.outcome = UDS_BOARD_OUTCOME_LINK_ERROR;
        uds_board_trace_finish(adapter);
        return false;
    }

    adapter->last_trace.egress_frame_valid = true;
    uds_board_trace_decode_response(&adapter->last_trace, &adapter->last_trace.egress_frame);
    *egress_frame_out = adapter->last_trace.egress_frame;
    adapter->last_trace.outcome = UDS_BOARD_OUTCOME_RESPONSE_READY;
    uds_board_trace_finish(adapter);
    return true;
}

static bool uds_board_adapter_process_gateway(
    uds_board_adapter_t *adapter,
    const uds_can_frame_t *ingress_frame,
    uds_can_frame_t *egress_frame_out
)
{
    uds_ecu_t *ecu;

    ecu = uds_board_task_ecu(adapter->adjacent_ecu_task);
    if (adapter->gateway_task == NULL || ecu == NULL) {
        adapter->last_trace.link_status = UDS_LINK_STATUS_INVALID_ARG;
        adapter->last_trace.outcome = UDS_BOARD_OUTCOME_LINK_ERROR;
        uds_board_trace_finish(adapter);
        return false;
    }

    adapter->last_trace.gateway_forwarded_request = uds_gateway_task_process_frame(
        adapter->gateway_task,
        ingress_frame,
        &adapter->last_trace.internal_request_frame
    );
    if (!adapter->last_trace.gateway_forwarded_request) {
        adapter->last_trace.gateway_blocked_request = adapter->gateway_task->gateway->last_frame_dropped;
        adapter->last_trace.gateway_blocked_sid = adapter->gateway_task->gateway->last_blocked_sid;
        adapter->last_trace.outcome = adapter->last_trace.gateway_blocked_request ?
            UDS_BOARD_OUTCOME_GATEWAY_BLOCKED :
            UDS_BOARD_OUTCOME_ENDPOINT_MISS;
        uds_board_trace_finish(adapter);
        return false;
    }

    adapter->last_trace.internal_request_valid = true;
    adapter->last_trace.ecu_request_accepted = uds_ecu_accepts_request_frame(
        ecu,
        &adapter->last_trace.internal_request_frame
    );
    if (!adapter->last_trace.ecu_request_accepted) {
        adapter->last_trace.link_status = UDS_LINK_STATUS_NOT_FOR_ENDPOINT;
        adapter->last_trace.outcome = UDS_BOARD_OUTCOME_ENDPOINT_MISS;
        uds_board_trace_finish(adapter);
        return false;
    }

    uds_board_trace_capture_phases(&adapter->last_trace, adapter->adjacent_ecu_task, true);
    adapter->last_trace.link_status = uds_ecu_task_process_frame(
        adapter->adjacent_ecu_task,
        &adapter->last_trace.internal_request_frame,
        &adapter->last_trace.internal_response_frame
    );
    uds_board_trace_capture_phases(&adapter->last_trace, adapter->adjacent_ecu_task, false);

    if (adapter->last_trace.link_status != UDS_LINK_STATUS_OK) {
        adapter->last_trace.outcome = UDS_BOARD_OUTCOME_LINK_ERROR;
        uds_board_trace_finish(adapter);
        return false;
    }

    adapter->last_trace.internal_response_valid = true;
    adapter->last_trace.gateway_forwarded_response = uds_gateway_task_process_frame(
        adapter->gateway_task,
        &adapter->last_trace.internal_response_frame,
        &adapter->last_trace.egress_frame
    );
    if (!adapter->last_trace.gateway_forwarded_response) {
        adapter->last_trace.outcome = UDS_BOARD_OUTCOME_LINK_ERROR;
        uds_board_trace_finish(adapter);
        return false;
    }

    adapter->last_trace.egress_frame_valid = true;
    uds_board_trace_decode_response(&adapter->last_trace, &adapter->last_trace.egress_frame);
    *egress_frame_out = adapter->last_trace.egress_frame;
    adapter->last_trace.outcome = UDS_BOARD_OUTCOME_RESPONSE_READY;
    uds_board_trace_finish(adapter);
    return true;
}

bool uds_board_adapter_process_ingress_frame(
    uds_board_adapter_t *adapter,
    const uds_can_frame_t *ingress_frame,
    uds_can_frame_t *egress_frame_out
)
{
    if (adapter == NULL || ingress_frame == NULL || egress_frame_out == NULL) {
        return false;
    }

    uds_board_trace_reset(&adapter->last_trace, adapter->path_mode, ingress_frame);

    if (adapter->control_hook != NULL &&
        adapter->control_hook(
            ingress_frame,
            egress_frame_out,
            adapter->control_hook_context)) {
        adapter->last_trace.egress_frame = *egress_frame_out;
        adapter->last_trace.egress_frame_valid = true;
        uds_board_trace_decode_response(&adapter->last_trace, egress_frame_out);
        adapter->last_trace.outcome = UDS_BOARD_OUTCOME_RESPONSE_READY;
        uds_board_trace_finish(adapter);
        return true;
    }

    if (adapter->path_mode == UDS_BOARD_PATH_DIRECT_ECU) {
        return uds_board_adapter_process_direct(adapter, ingress_frame, egress_frame_out);
    }

    return uds_board_adapter_process_gateway(adapter, ingress_frame, egress_frame_out);
}

bool uds_board_adapter_pump_once(
    uds_board_adapter_t *adapter,
    const uds_board_can_port_t *port
)
{
    uds_can_frame_t ingress_frame;
    uds_can_frame_t egress_frame;

    if (adapter == NULL || port == NULL ||
        port->receive_frame == NULL || port->send_frame == NULL) {
        return false;
    }

    if (!port->receive_frame(&ingress_frame, port->context)) {
        return false;
    }

    if (!uds_board_adapter_process_ingress_frame(
            adapter,
            &ingress_frame,
            &egress_frame)) {
        return false;
    }

    return port->send_frame(&egress_frame, port->context);
}

const uds_board_trace_t *uds_board_adapter_last_trace(
    const uds_board_adapter_t *adapter
)
{
    if (adapter == NULL) {
        return NULL;
    }

    return &adapter->last_trace;
}
