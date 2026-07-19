#include "uds_ecu.h"

void uds_ecu_init_strict(
    uds_ecu_t *ecu,
    uint32_t request_id,
    uint32_t response_id
)
{
    if (ecu == NULL) {
        return;
    }

    uds_ecu_link_init(&ecu->link, request_id, response_id);
    uds_dispatcher_init_strict(&ecu->dispatcher);
}

void uds_ecu_init_vulnerable(
    uds_ecu_t *ecu,
    uint32_t request_id,
    uint32_t response_id
)
{
    if (ecu == NULL) {
        return;
    }

    uds_ecu_link_init(&ecu->link, request_id, response_id);
    uds_dispatcher_init_vulnerable(&ecu->dispatcher);
}

void uds_ecu_activate_quarantine_policy(uds_ecu_t *ecu)
{
    if (ecu == NULL) {
        return;
    }

    uds_dispatcher_activate_quarantine_policy(&ecu->dispatcher);
}

bool uds_ecu_quarantine_policy_active(const uds_ecu_t *ecu)
{
    return ecu != NULL &&
        uds_dispatcher_quarantine_policy_active(&ecu->dispatcher);
}

bool uds_ecu_accepts_request_frame(
    const uds_ecu_t *ecu,
    const uds_can_frame_t *frame
)
{
    return ecu != NULL && uds_ecu_link_accepts_request(&ecu->link, frame);
}

uds_link_status_t uds_ecu_handle_request_frame(
    uds_ecu_t *ecu,
    const uds_can_frame_t *request_frame,
    uds_can_frame_t *response_frame_out
)
{
    uint8_t request_payload[UDS_CAN_SINGLE_FRAME_MAX_PAYLOAD];
    uint8_t request_length = 0U;
    uint8_t response_payload[UDS_CAN_SINGLE_FRAME_MAX_PAYLOAD];
    uint8_t response_length = 0U;
    uds_link_status_t status;

    if (ecu == NULL || request_frame == NULL || response_frame_out == NULL) {
        return UDS_LINK_STATUS_INVALID_ARG;
    }
    if (!uds_ecu_accepts_request_frame(ecu, request_frame)) {
        return UDS_LINK_STATUS_NOT_FOR_ENDPOINT;
    }

    status = uds_can_unpack_single_frame_payload(
        request_frame,
        request_payload,
        &request_length
    );
    if (status != UDS_LINK_STATUS_OK) {
        return status;
    }

    uds_dispatcher_handle_payload(
        &ecu->dispatcher,
        request_payload,
        request_length,
        response_payload,
        &response_length
    );

    return uds_ecu_link_build_response_frame(
        &ecu->link,
        response_payload,
        response_length,
        response_frame_out
    );
}
