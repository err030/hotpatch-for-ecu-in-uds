#include "uds_protocol.h"

#include <string.h>

static void uds_request_reset(uds_request_t *request)
{
    memset(request, 0, sizeof(*request));
}

bool uds_request_from_payload(
    uds_request_t *request,
    const uint8_t *payload,
    uint8_t payload_length
)
{
    if (request == NULL || payload == NULL || payload_length == 0U) {
        return false;
    }

    uds_request_reset(request);
    request->sid = payload[0];

    switch (request->sid) {
    case SID_DIAGNOSTIC_SESSION_CONTROL:
        if (payload_length != 2U) {
            return false;
        }
        request->has_subfunction = true;
        request->subfunction = payload[1];
        return true;

    case SID_SECURITY_ACCESS:
        if (payload_length < 2U) {
            return false;
        }
        request->has_subfunction = true;
        request->subfunction = payload[1];
        request->data_length = (uint8_t)(payload_length - 2U);
        if (request->data_length > UDS_MAX_SERVICE_DATA_LENGTH) {
            return false;
        }
        memcpy(request->data, &payload[2], request->data_length);
        return true;

    case SID_READ_DATA_BY_IDENTIFIER:
        if (payload_length != 3U) {
            return false;
        }
        request->has_did = true;
        request->did = (uint16_t)(((uint16_t)payload[1] << 8) | payload[2]);
        return true;

    case SID_WRITE_DATA_BY_IDENTIFIER:
        if (payload_length < 3U) {
            return false;
        }
        request->has_did = true;
        request->did = (uint16_t)(((uint16_t)payload[1] << 8) | payload[2]);
        request->data_length = (uint8_t)(payload_length - 3U);
        if (request->data_length > UDS_MAX_SERVICE_DATA_LENGTH) {
            return false;
        }
        memcpy(request->data, &payload[3], request->data_length);
        return true;

    default:
        request->data_length = (uint8_t)(payload_length - 1U);
        if (request->data_length > UDS_MAX_SERVICE_DATA_LENGTH) {
            return false;
        }
        memcpy(request->data, &payload[1], request->data_length);
        return true;
    }
}

bool uds_request_to_payload(
    const uds_request_t *request,
    uint8_t *payload_out,
    uint8_t *payload_length_out
)
{
    uint8_t cursor = 0U;

    if (request == NULL || payload_out == NULL || payload_length_out == NULL) {
        return false;
    }

    payload_out[cursor++] = request->sid;

    switch (request->sid) {
    case SID_DIAGNOSTIC_SESSION_CONTROL:
        if (!request->has_subfunction) {
            return false;
        }
        payload_out[cursor++] = request->subfunction;
        break;

    case SID_SECURITY_ACCESS:
        if (!request->has_subfunction) {
            return false;
        }
        payload_out[cursor++] = request->subfunction;
        memcpy(&payload_out[cursor], request->data, request->data_length);
        cursor = (uint8_t)(cursor + request->data_length);
        break;

    case SID_READ_DATA_BY_IDENTIFIER:
        if (!request->has_did) {
            return false;
        }
        payload_out[cursor++] = (uint8_t)(request->did >> 8);
        payload_out[cursor++] = (uint8_t)(request->did & 0xFFU);
        break;

    case SID_WRITE_DATA_BY_IDENTIFIER:
        if (!request->has_did) {
            return false;
        }
        payload_out[cursor++] = (uint8_t)(request->did >> 8);
        payload_out[cursor++] = (uint8_t)(request->did & 0xFFU);
        memcpy(&payload_out[cursor], request->data, request->data_length);
        cursor = (uint8_t)(cursor + request->data_length);
        break;

    default:
        memcpy(&payload_out[cursor], request->data, request->data_length);
        cursor = (uint8_t)(cursor + request->data_length);
        break;
    }

    *payload_length_out = cursor;
    return true;
}

bool uds_response_to_payload(
    const uds_response_t *response,
    uint8_t *payload_out,
    uint8_t *payload_length_out
)
{
    if (response == NULL || payload_out == NULL || payload_length_out == NULL) {
        return false;
    }

    if (!response->positive) {
        payload_out[0] = NEGATIVE_RESPONSE_SID;
        payload_out[1] = response->original_sid;
        payload_out[2] = response->nrc;
        *payload_length_out = 3U;
        return true;
    }

    payload_out[0] = response->sid;
    memcpy(&payload_out[1], response->data, response->data_length);
    *payload_length_out = (uint8_t)(1U + response->data_length);
    return true;
}

bool uds_response_from_payload(
    uds_response_t *response,
    const uint8_t *payload,
    uint8_t payload_length
)
{
    if (response == NULL || payload == NULL || payload_length == 0U) {
        return false;
    }

    memset(response, 0, sizeof(*response));
    response->sid = payload[0];

    if (payload[0] == NEGATIVE_RESPONSE_SID) {
        if (payload_length != 3U) {
            return false;
        }

        response->positive = false;
        response->original_sid = payload[1];
        response->nrc = payload[2];
        response->data_length = 2U;
        response->data[0] = payload[1];
        response->data[1] = payload[2];
        return true;
    }

    response->positive = true;
    response->data_length = (uint8_t)(payload_length - 1U);
    memcpy(response->data, &payload[1], response->data_length);
    return true;
}

uint8_t uds_positive_response_sid(uint8_t request_sid)
{
    return (uint8_t)(request_sid + 0x40U);
}

void uds_response_make_positive(
    uds_response_t *response,
    uint8_t request_sid,
    const uint8_t *data,
    uint8_t data_length
)
{
    if (response == NULL) {
        return;
    }

    memset(response, 0, sizeof(*response));
    response->positive = true;
    response->sid = uds_positive_response_sid(request_sid);
    response->data_length = data_length;
    if (data != NULL && data_length > 0U) {
        memcpy(response->data, data, data_length);
    }
}

void uds_response_make_negative(
    uds_response_t *response,
    uint8_t request_sid,
    uint8_t nrc
)
{
    if (response == NULL) {
        return;
    }

    memset(response, 0, sizeof(*response));
    response->positive = false;
    response->sid = NEGATIVE_RESPONSE_SID;
    response->original_sid = request_sid;
    response->nrc = nrc;
}
