#include "board_log.h"

#ifdef BOARD_LOG_USE_SEGGER_RTT

#include <stddef.h>

#include "SEGGER_RTT.h"

void board_log_write(const char *message)
{
    if (message == NULL) {
        return;
    }

    SEGGER_RTT_WriteString(0, message);
}

#endif
