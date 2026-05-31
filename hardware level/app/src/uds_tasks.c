#include "uds_tasks.h"

void uds_ecu_task_init(
    uds_ecu_task_t *task,
    uds_ecu_t *ecu
)
{
    if (task == NULL) {
        return;
    }

    task->ecu = ecu;
}

void uds_gateway_task_init(
    uds_gateway_task_t *task,
    uds_gateway_t *gateway
)
{
    if (task == NULL) {
        return;
    }

    task->gateway = gateway;
}

uds_link_status_t uds_ecu_task_process_frame(
    uds_ecu_task_t *task,
    const uds_can_frame_t *request_frame,
    uds_can_frame_t *response_frame_out
)
{
    if (task == NULL || task->ecu == NULL) {
        return UDS_LINK_STATUS_INVALID_ARG;
    }

    return uds_ecu_handle_request_frame(task->ecu, request_frame, response_frame_out);
}

bool uds_gateway_task_process_frame(
    uds_gateway_task_t *task,
    const uds_can_frame_t *input_frame,
    uds_can_frame_t *output_frame
)
{
    if (task == NULL || task->gateway == NULL) {
        return false;
    }

    return uds_gateway_forward_frame(task->gateway, input_frame, output_frame);
}

bool uds_diag_path_process_external_request(
    uds_gateway_task_t *gateway_task,
    uds_ecu_task_t *adjacent_ecu_task,
    const uds_can_frame_t *tester_request_frame,
    uds_can_frame_t *tester_response_frame_out
)
{
    uds_can_frame_t internal_request_frame;
    uds_can_frame_t internal_response_frame;

    if (gateway_task == NULL ||
        adjacent_ecu_task == NULL ||
        tester_request_frame == NULL ||
        tester_response_frame_out == NULL) {
        return false;
    }

    if (!uds_gateway_task_process_frame(
            gateway_task,
            tester_request_frame,
            &internal_request_frame)) {
        return false;
    }

    if (uds_ecu_task_process_frame(
            adjacent_ecu_task,
            &internal_request_frame,
            &internal_response_frame) != UDS_LINK_STATUS_OK) {
        return false;
    }

    return uds_gateway_task_process_frame(
        gateway_task,
        &internal_response_frame,
        tester_response_frame_out
    );
}
