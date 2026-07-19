#ifndef UDS_TASKS_H
#define UDS_TASKS_H

#include <stdbool.h>

#include "uds_ecu.h"
#include "uds_gateway.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uds_ecu_t *ecu;
} uds_ecu_task_t;

typedef struct {
    uds_gateway_t *gateway;
} uds_gateway_task_t;

void uds_ecu_task_init(
    uds_ecu_task_t *task,
    uds_ecu_t *ecu
);

void uds_gateway_task_init(
    uds_gateway_task_t *task,
    uds_gateway_t *gateway
);

uds_link_status_t uds_ecu_task_process_frame(
    uds_ecu_task_t *task,
    const uds_can_frame_t *request_frame,
    uds_can_frame_t *response_frame_out
);

bool uds_gateway_task_process_frame(
    uds_gateway_task_t *task,
    const uds_can_frame_t *input_frame,
    uds_can_frame_t *output_frame
);

bool uds_diag_path_process_external_request(
    uds_gateway_task_t *gateway_task,
    uds_ecu_task_t *adjacent_ecu_task,
    const uds_can_frame_t *tester_request_frame,
    uds_can_frame_t *tester_response_frame_out
);

#ifdef __cplusplus
}
#endif

#endif
