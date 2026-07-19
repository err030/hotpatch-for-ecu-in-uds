#include "uds_link.h"

#include <string.h>

#define UDS_ISOTP_FRAME_TYPE_SINGLE 0x0U
#define UDS_ISOTP_FRAME_TYPE_FIRST 0x1U

uds_link_status_t uds_can_frame_init(
    uds_can_frame_t *frame,
    uint32_t arbitration_id,
    const uint8_t *data,
    uint8_t dlc
)
{
    if (frame == NULL) {
        return UDS_LINK_STATUS_INVALID_ARG;
    }
    if (dlc > UDS_CAN_MAX_DATA_LENGTH) {
        return UDS_LINK_STATUS_DLC_TOO_LARGE;
    }

    memset(frame, 0, sizeof(*frame));
    frame->arbitration_id = arbitration_id;
    frame->dlc = dlc;
    if (data != NULL && dlc > 0U) {
        memcpy(frame->data, data, dlc);
    }
    return UDS_LINK_STATUS_OK;
}

uds_link_status_t uds_can_pack_single_frame_payload(
    uds_can_frame_t *frame_out,
    uint32_t arbitration_id,
    const uint8_t *payload,
    uint8_t payload_length
)
{
    uint8_t encoded[UDS_CAN_MAX_DATA_LENGTH] = {0U};

    if (frame_out == NULL) {
        return UDS_LINK_STATUS_INVALID_ARG;
    }
    if (payload_length > UDS_CAN_SINGLE_FRAME_MAX_PAYLOAD) {
        return UDS_LINK_STATUS_PAYLOAD_TOO_LARGE;
    }
    if (payload_length > 0U && payload == NULL) {
        return UDS_LINK_STATUS_INVALID_ARG;
    }

    encoded[0] = payload_length;
    if (payload_length > 0U) {
        memcpy(&encoded[1], payload, payload_length);
    }
    return uds_can_frame_init(frame_out, arbitration_id, encoded, UDS_CAN_MAX_DATA_LENGTH);
}

uds_link_status_t uds_can_unpack_single_frame_payload(
    const uds_can_frame_t *frame,
    uint8_t *payload_out,
    uint8_t *payload_length_out
)
{
    uint8_t payload_length;

    if (frame == NULL || payload_length_out == NULL) {
        return UDS_LINK_STATUS_INVALID_ARG;
    }
    if (frame->dlc == 0U || frame->dlc > UDS_CAN_MAX_DATA_LENGTH) {
        return UDS_LINK_STATUS_DLC_TOO_LARGE;
    }
    if ((frame->data[0] >> 4) != UDS_ISOTP_FRAME_TYPE_SINGLE) {
        return UDS_LINK_STATUS_UNSUPPORTED_PCI;
    }

    payload_length = (uint8_t)(frame->data[0] & 0x0FU);
    if (payload_length > UDS_CAN_SINGLE_FRAME_MAX_PAYLOAD) {
        return UDS_LINK_STATUS_PAYLOAD_TOO_LARGE;
    }
    if ((uint8_t)(1U + payload_length) > frame->dlc) {
        return UDS_LINK_STATUS_DLC_TOO_LARGE;
    }
    if (payload_length > 0U && payload_out == NULL) {
        return UDS_LINK_STATUS_INVALID_ARG;
    }

    if (payload_length > 0U) {
        memcpy(payload_out, &frame->data[1], payload_length);
    }
    *payload_length_out = payload_length;
    return UDS_LINK_STATUS_OK;
}

bool uds_can_extract_service_id(
    const uds_can_frame_t *frame,
    uint8_t *sid_out
)
{
    uint8_t pci_type;

    if (frame == NULL || sid_out == NULL || frame->dlc == 0U) {
        return false;
    }

    pci_type = (uint8_t)(frame->data[0] >> 4);
    if (pci_type == UDS_ISOTP_FRAME_TYPE_SINGLE) {
        if (frame->dlc < 2U) {
            return false;
        }
        *sid_out = frame->data[1];
        return true;
    }

    if (pci_type == UDS_ISOTP_FRAME_TYPE_FIRST) {
        if (frame->dlc < 3U) {
            return false;
        }
        *sid_out = frame->data[2];
        return true;
    }

    return false;
}

void uds_ecu_link_init(
    uds_ecu_link_t *link,
    uint32_t request_id,
    uint32_t response_id
)
{
    if (link == NULL) {
        return;
    }

    link->request_id = request_id;
    link->response_id = response_id;
}

bool uds_ecu_link_accepts_request(
    const uds_ecu_link_t *link,
    const uds_can_frame_t *frame
)
{
    return link != NULL && frame != NULL && frame->arbitration_id == link->request_id;
}

uds_link_status_t uds_ecu_link_build_response_frame(
    const uds_ecu_link_t *link,
    const uint8_t *payload,
    uint8_t payload_length,
    uds_can_frame_t *response_frame_out
)
{
    if (link == NULL) {
        return UDS_LINK_STATUS_INVALID_ARG;
    }

    return uds_can_pack_single_frame_payload(
        response_frame_out,
        link->response_id,
        payload,
        payload_length
    );
}
