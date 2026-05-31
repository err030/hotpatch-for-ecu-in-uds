#include "hp_applicator.h"
#include "hp_port.h"

volatile struct hp_applicator_context  g_applicator_context;

void
__ramfunc
hp_applicator_reset_context(void) {
    g_applicator_context.status = HP_APPLICATOR_CONTEXT_INACTIVE;
    g_applicator_context.entry.target_address = 0;
    for (uint32_t i = 0; i < HP_APPLICATOR_DATA_LENGTH; i++) {
        g_applicator_context.entry.hotpatch_data[i] = 0;
    }
}

void
__ramfunc
hp_applicator_init(void) {
    // reset the context of the hotpatches
    hp_applicator_reset_context();
}

void inline
__ramfunc
//__attribute__((soptimize("O0")))
hp_applicator_hotpatch_apply(void) {
    uint32_t lo, hi;
    uint32_t target_address, hotpatch_data;

    target_address = g_applicator_context.entry.target_address;
    hotpatch_data  = (uint32_t)&g_applicator_context.entry.hotpatch_data;

    __asm__ volatile(
        "ldm    %[data], {%[lo], %[hi]}\n"
        "strh   %[lo], [%[addr]]\n"
        "lsr    %[lo], #16\n"
        "strh   %[lo], [%[addr], #2]\n"
        "strh   %[hi], [%[addr], #4]\n"
        "lsr    %[hi], #16\n"
        "strh   %[hi], [%[addr], #6]\n"
        : [lo] "=&r" (lo),
          [hi] "=&r" (hi)
        : [addr] "r" (target_address),
          [data] "r" (hotpatch_data)
        :
    );

    g_applicator_context.status = HP_APPLICATOR_CONTEXT_INACTIVE;
}
