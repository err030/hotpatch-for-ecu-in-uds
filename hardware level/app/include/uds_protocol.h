#ifndef UDS_PROTOCOL_H
#define UDS_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UDS_MAX_SERVICE_DATA_LENGTH 32U
#define UDS_MAX_PAYLOAD_LENGTH (3U + UDS_MAX_SERVICE_DATA_LENGTH)

#define SID_DIAGNOSTIC_SESSION_CONTROL 0x10U
#define SID_READ_DATA_BY_IDENTIFIER 0x22U
#define SID_SECURITY_ACCESS 0x27U
#define SID_WRITE_DATA_BY_IDENTIFIER 0x2EU
#define NEGATIVE_RESPONSE_SID 0x7FU

#define SESSION_DEFAULT 0x01U
#define SESSION_EXTENDED 0x03U

#define NRC_SUBFUNCTION_NOT_SUPPORTED 0x12U
#define NRC_INCORRECT_MESSAGE_LENGTH 0x13U
#define NRC_CONDITIONS_NOT_CORRECT 0x22U
#define NRC_REQUEST_SEQUENCE_ERROR 0x24U
#define NRC_REQUEST_OUT_OF_RANGE 0x31U
#define NRC_SECURITY_ACCESS_DENIED 0x33U
#define NRC_INVALID_KEY 0x35U
#define NRC_EXCEED_NUMBER_OF_ATTEMPTS 0x36U
#define NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED 0x37U

typedef struct {
    uint8_t sid;
    bool has_subfunction;
    uint8_t subfunction;
    bool has_did;
    uint16_t did;
    uint8_t data_length;
    uint8_t data[UDS_MAX_SERVICE_DATA_LENGTH];
} uds_request_t;

typedef struct {
    bool positive;
    uint8_t sid;
    uint8_t data_length;
    uint8_t data[UDS_MAX_SERVICE_DATA_LENGTH];
    uint8_t original_sid;
    uint8_t nrc;
} uds_response_t;

bool uds_request_from_payload(
    uds_request_t *request,
    const uint8_t *payload,
    uint8_t payload_length
);

bool uds_request_to_payload(
    const uds_request_t *request,
    uint8_t *payload_out,
    uint8_t *payload_length_out
);

bool uds_response_to_payload(
    const uds_response_t *response,
    uint8_t *payload_out,
    uint8_t *payload_length_out
);

bool uds_response_from_payload(
    uds_response_t *response,
    const uint8_t *payload,
    uint8_t payload_length
);

uint8_t uds_positive_response_sid(uint8_t request_sid);

void uds_response_make_positive(
    uds_response_t *response,
    uint8_t request_sid,
    const uint8_t *data,
    uint8_t data_length
);

void uds_response_make_negative(
    uds_response_t *response,
    uint8_t request_sid,
    uint8_t nrc
);

#ifdef __cplusplus
}
#endif

#endif
