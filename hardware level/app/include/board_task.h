#ifndef BOARD_TASK_H
#define BOARD_TASK_H

#include <stdint.h>

#include "board_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*uds_board_delay_hook_t)(
    uint32_t delay_ticks,
    void *context
);

typedef struct {
    uds_board_runtime_t *runtime;
    uint32_t idle_delay_ticks;
    uds_board_delay_hook_t delay_hook;
    void *delay_context;
} uds_board_task_context_t;

void uds_board_task_run_once(
    uds_board_task_context_t *context
);

void uds_board_task_run_forever(
    uds_board_task_context_t *context
);

#ifdef BOARD_USE_FREERTOS
void uds_board_freertos_task(void *parameter);
#endif

#ifdef __cplusplus
}
#endif

#endif
