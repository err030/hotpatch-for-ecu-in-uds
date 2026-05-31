#include "board_trace_log.h"

#include "board_log.h"

static const char *board_trace_outcome_name(uds_board_outcome_t outcome)
{
    switch (outcome) {
    case UDS_BOARD_OUTCOME_NONE:
        return "none";
    case UDS_BOARD_OUTCOME_RESPONSE_READY:
        return "response_ready";
    case UDS_BOARD_OUTCOME_GATEWAY_BLOCKED:
        return "gateway_blocked";
    case UDS_BOARD_OUTCOME_ENDPOINT_MISS:
        return "endpoint_miss";
    case UDS_BOARD_OUTCOME_LINK_ERROR:
        return "link_error";
    default:
        return "unknown";
    }
}

static const char *board_trace_phase_name(uds_security_phase_t phase)
{
    switch (phase) {
    case UDS_SECURITY_PHASE_DEFAULT_SESSION:
        return "default_session";
    case UDS_SECURITY_PHASE_EXTENDED_SESSION:
        return "extended_session";
    case UDS_SECURITY_PHASE_SEED_ISSUED:
        return "seed_issued";
    case UDS_SECURITY_PHASE_UNLOCKED:
        return "unlocked";
    case UDS_SECURITY_PHASE_LOCKED_OUT:
        return "locked_out";
    default:
        return "unknown";
    }
}

void board_trace_log_sink(
    const uds_board_trace_t *trace,
    void *context
)
{
    (void)context;

    if (trace == NULL || !trace->valid) {
        return;
    }

    board_log_printf(
        "[UDS][RX] path=%s can_id=0x%03lX sid=%s0x%02X dlc=%u\n",
        trace->path_mode == UDS_BOARD_PATH_DIRECT_ECU ? "direct" : "gateway",
        (unsigned long)trace->ingress_frame.arbitration_id,
        trace->ingress_sid_valid ? "" : "unknown:",
        trace->ingress_sid_valid ? trace->ingress_sid : 0U,
        trace->ingress_frame.dlc
    );

    if (trace->gateway_forwarded_request) {
        board_log_printf(
            "[UDS][GW] forwarded request to internal_id=0x%03lX\n",
            (unsigned long)trace->internal_request_frame.arbitration_id
        );
    }

    if (trace->gateway_blocked_request) {
        board_log_printf(
            "[UDS][GW] blocked sid=0x%02X\n",
            trace->gateway_blocked_sid
        );
    }

    board_log_printf(
        "[UDS][ECU] accepted=%s phase=%s->%s outcome=%s link_status=%d\n",
        trace->ecu_request_accepted ? "yes" : "no",
        board_trace_phase_name(trace->ecu_phase_before),
        board_trace_phase_name(trace->ecu_phase_after),
        board_trace_outcome_name(trace->outcome),
        (int)trace->link_status
    );

    if (!trace->egress_frame_valid) {
        return;
    }

    if (trace->response_decoded) {
        if (trace->uds_response.positive) {
            board_log_printf(
                "[UDS][TX] can_id=0x%03lX positive_sid=0x%02X data_len=%u\n",
                (unsigned long)trace->egress_frame.arbitration_id,
                trace->uds_response.sid,
                trace->uds_response.data_length
            );
        } else {
            board_log_printf(
                "[UDS][TX] can_id=0x%03lX negative_sid=0x%02X original_sid=0x%02X nrc=0x%02X\n",
                (unsigned long)trace->egress_frame.arbitration_id,
                trace->uds_response.sid,
                trace->uds_response.original_sid,
                trace->uds_response.nrc
            );
        }
        return;
    }

    board_log_printf(
        "[UDS][TX] can_id=0x%03lX undecoded_response dlc=%u\n",
        (unsigned long)trace->egress_frame.arbitration_id,
        trace->egress_frame.dlc
    );
}
