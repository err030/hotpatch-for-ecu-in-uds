#ifndef BOARD_TRACE_LOG_H
#define BOARD_TRACE_LOG_H

#include "board_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

void board_trace_log_sink(
    const uds_board_trace_t *trace,
    void *context
);

#ifdef __cplusplus
}
#endif

#endif
