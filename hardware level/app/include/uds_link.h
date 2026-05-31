#ifndef UDS_LINK_H
#define UDS_LINK_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UDS_CAN_MAX_DATA_LENGTH 8U
#define UDS_CAN_SINGLE_FRAME_MAX_PAYLOAD 7U

typedef enum {
    UDS_LINK_STATUS_OK = 0,
    UDS_LINK_STATUS_INVALID_ARG,
    UDS_LINK_STATUS_DLC_TOO_LARGE,
    UDS_LINK_STATUS_PAYLOAD_TOO_LARGE,
    UDS_LINK_STATUS_UNSUPPORTED_PCI,
    UDS_LINK_STATUS_NOT_FOR_ENDPOINT,
} uds_link_status_t;

typedef struct {
    uint32_t arbitration_id;
    uint8_t dlc;
    uint8_t data[UDS_CAN_MAX_DATA_LENGTH];
} uds_can_frame_t;

typedef struct {
    uint32_t request_id;
    uint32_t response_id;
} uds_ecu_link_t;

typedef struct {
    uint32_t external_request_id;
    uint32_t internal_request_id;
    uint32_t internal_response_id;
    uint32_t external_response_id;
} uds_gateway_route_t;

uds_link_status_t uds_can_frame_init(
    uds_can_frame_t *frame,
    uint32_t arbitration_id,
    const uint8_t *data,
    uint8_t dlc
);

uds_link_status_t uds_can_pack_single_frame_payload(
    uds_can_frame_t *frame_out,
    uint32_t arbitration_id,
    const uint8_t *payload,
    uint8_t payload_length
);

uds_link_status_t uds_can_unpack_single_frame_payload(
    const uds_can_frame_t *frame,
    uint8_t *payload_out,
    uint8_t *payload_length_out
);

bool uds_can_extract_service_id(
    const uds_can_frame_t *frame,
    uint8_t *sid_out
);

void uds_ecu_link_init(
    uds_ecu_link_t *link,
    uint32_t request_id,
    uint32_t response_id
);

bool uds_ecu_link_accepts_request(
    const uds_ecu_link_t *link,
    const uds_can_frame_t *frame
);

uds_link_status_t uds_ecu_link_build_response_frame(
    const uds_ecu_link_t *link,
    const uint8_t *payload,
    uint8_t payload_length,
    uds_can_frame_t *response_frame_out
);

#ifdef __cplusplus
}
#endif

#endif
