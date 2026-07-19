#include "board_log.h"

#include <stdio.h>

void __attribute__((weak)) board_log_write(const char *message)
{
    if (message == NULL) {
        return;
    }

    fputs(message, stdout);
}

void board_log_vprintf(const char *format, va_list args)
{
    char buffer[256];
    int written;

    if (format == NULL) {
        return;
    }

    written = vsnprintf(buffer, sizeof(buffer), format, args);
    if (written <= 0) {
        return;
    }

    board_log_write(buffer);
}

void board_log_printf(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    board_log_vprintf(format, args);
    va_end(args);
}
