#ifndef BOARD_LOG_H
#define BOARD_LOG_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

void board_log_write(const char *message);
void board_log_vprintf(const char *format, va_list args);
void board_log_printf(const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
