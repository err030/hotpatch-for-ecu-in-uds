#include "uds_gateway.h"

#include "uds_protocol.h"

static bool uds_gateway_service_allowed(
    uds_gateway_mode_t mode,
    uint8_t sid
)
{
    switch (mode) {
    case UDS_GATEWAY_MODE_OPEN:
        return true;

    case UDS_GATEWAY_MODE_RESTRICTED:
        return sid == SID_DIAGNOSTIC_SESSION_CONTROL ||
               sid == SID_READ_DATA_BY_IDENTIFIER ||
               sid == SID_SECURITY_ACCESS ||
               sid == SID_TESTER_PRESENT;

    case UDS_GATEWAY_MODE_MISCONFIGURED:
        return sid == SID_DIAGNOSTIC_SESSION_CONTROL ||
               sid == SID_READ_DATA_BY_IDENTIFIER ||
               sid == SID_SECURITY_ACCESS ||
               sid == SID_WRITE_DATA_BY_IDENTIFIER ||
               sid == SID_TESTER_PRESENT;

    default:
        return false;
    }
}

void uds_gateway_init(
    uds_gateway_t *gateway,
    const uds_gateway_route_t *route,
    uds_gateway_mode_t mode
)
{
    if (gateway == NULL || route == NULL) {
        return;
    }

    gateway->route = *route;
    gateway->mode = mode;
    gateway->last_frame_dropped = false;
    gateway->last_blocked_sid = 0U;
}

bool uds_gateway_forward_frame(
    uds_gateway_t *gateway,
    const uds_can_frame_t *input_frame,
    uds_can_frame_t *output_frame
)
{
    uint8_t sid = 0U;
    uds_link_status_t status;

    if (gateway == NULL || input_frame == NULL || output_frame == NULL) {
        return false;
    }

    gateway->last_frame_dropped = false;
    gateway->last_blocked_sid = 0U;

    if (input_frame->arbitration_id == gateway->route.external_request_id) {
        if (uds_can_extract_service_id(input_frame, &sid) &&
            !uds_gateway_service_allowed(gateway->mode, sid)) {
            gateway->last_frame_dropped = true;
            gateway->last_blocked_sid = sid;
            return false;
        }

        status = uds_can_frame_init(
            output_frame,
            gateway->route.internal_request_id,
            input_frame->data,
            input_frame->dlc
        );
        return status == UDS_LINK_STATUS_OK;
    }

    if (input_frame->arbitration_id == gateway->route.internal_response_id) {
        status = uds_can_frame_init(
            output_frame,
            gateway->route.external_response_id,
            input_frame->data,
            input_frame->dlc
        );
        return status == UDS_LINK_STATUS_OK;
    }

    return false;
}
