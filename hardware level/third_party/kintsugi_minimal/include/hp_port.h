#ifndef HP_PORT_H_
#define HP_PORT_H_

#include "hp_config.h"

#if (HP_CONFIG_ZEPHYROS == 1)

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/logging/log_internal.h>
#include <zephyr/linker/linker-defs.h>

#define hp_malloc   malloc
#define hp_free     free


#if (HP_CONFIG_LOG == 1)
#define DEBUG_LOG(...) printk(__VA_ARGS__)
#else
#define DEBUG_LOG(...) do {} while (0)
#endif
//printk(__VA_ARGS__)

//do {} while (0)

//printk(__VA_ARGS__)

#elif (HP_CONFIG_FREERTOS == 1)

#include "FreeRTOS.h"
#include "task.h"
#include "portable.h"

#ifndef HP_TARGET_CRAZYFLY
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_delay.h"
#include "nrf.h"
#endif


#define __ramfunc __attribute__((section(".ramfunc")))


extern uint32_t UART_PRINT_FLAG;

#if (HP_CONFIG_LOG == 1)
#define DEBUG_LOG(...) printf(__VA_ARGS__)

/*
{ \
UART_PRINT_FLAG = 1;\
printf(__VA_ARGS__);\
while (UART_PRINT_FLAG != 0) {\
    nrf_delay_ms(5);\
}\
}\
while(0)
*/
#else
#define DEBUG_LOG(...) do {} while (0)
#endif

/*\ 
{ \
UART_PRINT_FLAG = 1;\
printf(__VA_ARGS__);\
while (UART_PRINT_FLAG != 0) {\
    nrf_delay_ms(1);\
}\
}\
while(0)
*/

//printf(__VA_ARGS__)
//do {} while (false)
//printf(__VA_ARGS__);
/*
\ 
{ \
UART_PRINT_FLAG = 1;\
printf(__VA_ARGS__);\
while (UART_PRINT_FLAG != 0) {\
    nrf_delay_ms(1);\
}\
}\
while(0)
*/
//do {} while(false) //

#define hp_malloc    pvPortMalloc
#define hp_free      vPortFree

#define hotpatchYIELD   portYIELD() // do {} while (false) // vTaskDelay(100)



extern const char __ramfunc_start[];
extern const char __ramfunc_end[];
extern const char __ramfunc_size[];
extern const char __ramfunc_load_start[];

#if (HP_TARGET_CRAZYFLIE == 1)
#include "static_mem.h"
#endif


#endif

extern const char __text_start[];
extern const char __text_end[];
extern const char __text_size[];

extern const char __hotpatch_slots_start[];
extern const char __hotpatch_slots_end[];
extern const char __hotpatch_slots_size[];
extern const char __hotpatch_slots_load_start[];

extern const char __hotpatch_code_start[];
extern const char __hotpatch_code_end[];
extern const char __hotpatch_code_size[];
extern const char __hotpatch_code_load_start[];

extern const char __hotpatch_context_start[];
extern const char __hotpatch_context_end[];
extern const char __hotpatch_context_size[];
extern const char __hotpatch_context_load_start[];

extern const char __hotpatch_quarantine_start[];
extern const char __hotpatch_quarantine_end[];
extern const char __hotpatch_quarantine_size[];

extern const char __hotpatch_slots_quarantine_start[];
extern const char __hotpatch_slots_quarantine_end[];
extern const char __hotpatch_slots_quarantine_size[];

#endif // HP_PORT_H_