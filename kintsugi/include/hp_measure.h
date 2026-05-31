#ifndef HP_MEASURE_H_
#define HP_MEASURE_H_

#include "hp_def.h"
#include "hp_config.h"
#include "hp_port.h"

#if defined(HP_MEASURE_NUM_ITERATIONS)

extern uint32_t hp_measure_list[HP_MEASURE_NUM_ITERATIONS];
extern uint32_t hp_measure_index, hp_measure_time_start, hp_measure_time_end;

__attribute__((always_inline)) inline void 
hp_measure_reset(void) {
    for (uint32_t i = 0; i < HP_MEASURE_NUM_ITERATIONS; i++) {
        hp_measure_list[i] = 0;
    }
}

__attribute__((always_inline)) inline void hp_enable_irq(void)
{
  __asm__ volatile ("cpsie i");
}

__attribute__((always_inline)) inline void hp_disable_irq(void)
{
  __asm__ volatile ("cpsid i");
}

__attribute__((always_inline)) inline void
hp_measure_start(void) {
    hp_disable_irq();

    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0; 
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    hp_measure_time_start = DWT->CYCCNT;
}

__attribute__((always_inline)) inline void
hp_measure_stop(void) {
    hp_measure_time_end = DWT->CYCCNT;

    if (hp_measure_index < HP_MEASURE_NUM_ITERATIONS) {
        hp_measure_list[hp_measure_index++] = hp_measure_time_end - hp_measure_time_start;
    }

    //hp_measure_cycles_stop = DWT->CYCCNT;
    DWT->CTRL &= ~DWT_CTRL_CYCCNTENA_Msk;
    CoreDebug->DEMCR &= ~CoreDebug_DEMCR_TRCENA_Msk;

    hp_enable_irq();
}

__attribute__((always_inline)) inline void
hp_measure_start_irq(void) {
    
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0; 
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    hp_measure_time_start = DWT->CYCCNT;
}

__attribute__((always_inline)) inline void
hp_measure_stop_irq(void) {
    hp_measure_time_end = DWT->CYCCNT;

    if (hp_measure_index < HP_MEASURE_NUM_ITERATIONS) {
        hp_measure_list[hp_measure_index++] = hp_measure_time_end - hp_measure_time_start;
    }

    //hp_measure_cycles_stop = DWT->CYCCNT;
    DWT->CTRL &= ~DWT_CTRL_CYCCNTENA_Msk;
    CoreDebug->DEMCR &= ~CoreDebug_DEMCR_TRCENA_Msk;

}

__attribute__((always_inline)) inline uint32_t
hp_measure_get(void) {
    return DWT->CYCCNT;
}

__attribute__((always_inline)) inline void
hp_measure_reset_index(void) {
    hp_measure_index = 0;
}

__attribute__((always_inline)) inline uint32_t
hp_measure_get_list_item(uint32_t index) {
    if (index < HP_MEASURE_NUM_ITERATIONS) {
        return hp_measure_list[index];
    }
    return 0;
}

__attribute__((always_inline)) inline void
hp_measure_output(void) {
    printf("%d\r\n", hp_measure_index);
    if (hp_measure_index >= 5) {
        for (uint32_t i = 0; i < HP_MEASURE_NUM_ITERATIONS; i++) {
            printf("%d\r\n", hp_measure_list[i]);
            nrf_delay_ms(5);
        }

        while (1) {};
    }
}

#endif
#endif // HP_MEASURE_H_