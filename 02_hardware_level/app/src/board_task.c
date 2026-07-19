#include "board_task.h"

#ifdef BOARD_USE_FREERTOS
#include "FreeRTOS.h"
#include "task.h"
#endif

void uds_board_task_run_once(
    uds_board_task_context_t *context
)
{
    uds_board_runtime_poll_result_t result;

    if (context == NULL || context->runtime == NULL) {
        return;
    }

    result = uds_board_runtime_poll_once(context->runtime);
    if (result == UDS_BOARD_RUNTIME_IDLE &&
        context->delay_hook != NULL &&
        context->idle_delay_ticks > 0U) {
        context->delay_hook(context->idle_delay_ticks, context->delay_context);
    }
}

void uds_board_task_run_forever(
    uds_board_task_context_t *context
)
{
    if (context == NULL) {
        return;
    }

    for (;;) {
        uds_board_task_run_once(context);
    }
}

#ifdef BOARD_USE_FREERTOS
void uds_board_freertos_task(void *parameter)
{
    uds_board_task_context_t *context = (uds_board_task_context_t *)parameter;

    if (context == NULL) {
        vTaskDelete(NULL);
        return;
    }

    for (;;) {
        uds_board_runtime_poll_result_t result = uds_board_runtime_poll_once(context->runtime);
        if (result == UDS_BOARD_RUNTIME_IDLE && context->idle_delay_ticks > 0U) {
            vTaskDelay(context->idle_delay_ticks);
        }
    }
}
#endif
