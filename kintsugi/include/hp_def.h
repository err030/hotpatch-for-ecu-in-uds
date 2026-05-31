#ifndef HP_DEF_H_
#define HP_DEF_H_

#include <stdint.h>
#include <string.h>

#define TRUE    1
#define FALSE   0

#define __pack  __attribute__ ((__packed__))
#define __ni    __attribute__ ((noinline))

#ifndef __ramfunc
#define __ramfunc __attribute__((section(".ramfunc")))
#endif


#define HP_SLOT_START   ((uint32_t)&__hotpatch_slots_start)
#define HP_SLOT_END     ((uint32_t)&__hotpatch_slots_end)
#define HP_SLOT_SIZE    ((uint32_t)&__hotpatch_slots_size)

#define HP_CODE_START   ((uint32_t)&__hotpatch_code_start)
#define HP_CODE_END     ((uint32_t)&__hotpatch_code_end)
#define HP_CODE_SIZE    ((uint32_t)&__hotpatch_code_size)

#define HP_CONTEXT_START    ((uint32_t)&__hotpatch_context_start)
#define HP_CONTEXT_END      ((uint32_t)&__hotpatch_context_end)
#define HP_CONTEXT_SIZE     ((uint32_t)&__hotpatch_context_size)

#define HP_QUARANTINE_START ((uint32_t)&__hotpatch_quarantine_start)
#define HP_QUARANTINE_END   ((uint32_t)&__hotpatch_quarantine_end)
#define HP_QUARANTINE_SIZE  ((uint32_t)&__hotpatch_quarantine_size)

#define HP_RAMFUNC_START    ((uint32_t)&__ramfunc_start)
#define HP_RAMFUNC_END      ((uint32_t)&__ramfunc_end)
#define HP_RAMFUNC_SIZE     ((uint32_t)&__ramfunc_size)

#define __hotpatch_slots        __attribute__((section(".hotpatch_slots")))
#define __hotpatch_code         __attribute__((section(".hotpatch_code")))
#define __hotpatch_context      __attribute__((section(".hotpatch_context")))
#define __hotpatch_quarantine   __attribute__((section(".hotpatch_quarantine")))

#define __isb() __asm__ volatile("isb\n")
#define __dsb() __asm__ volatile("dsb\n");

enum hp_type {
    HP_TYPE_REPLACEMENT = 0,
    HP_TYPE_REDIRECT
};

#define hp_valid_type(x) ((x) == HP_TYPE_REDIRECT || (x) == HP_TYPE_REPLACEMENT)


struct __pack hp_header {
    uint32_t type;              // type of the hotpatch
    uint32_t target_address;    // address to hotpatch
    uint32_t code_size;         // size of the hotpatch code
    uint8_t *code_ptr;          // pointer to the hotpatch code
};

#define HP_HEADER_SIZE      (sizeof(struct hp_header))
#define HP_QUARANTINE_ENTRY_SIZE  (HP_MAX_CODE_SIZE + sizeof(struct hp_header))

//#define HP_MAX_CODE_SIZE    512
#define HP_MAX_SIZE         (sizeof(struct hp_header) + HP_MAX_CODE_SIZE)
#define HP_MAGIC            0x48504657

#define align_up(num, alignment) (((num) + ((alignment) - 1)) & ~((alignment) - 1))

#endif // HP_DEF_H_