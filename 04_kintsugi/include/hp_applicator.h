#ifndef HP_APPLICATOR_H_
#define HP_APPLICATOR_H_

#include "hp_def.h"
#include "hp_config.h"

#define HP_APPLICATOR_DATA_LENGTH 8
//#define HP_APPLICATOR_ENTRY_COUNT 5

enum hp_applicator_context_status {
    HP_APPLICATOR_CONTEXT_INACTIVE = 0,
    HP_APPLCIATOR_CONTEXT_ACTIVE,
};

struct __pack hp_applicator_context_entry {
    uint32_t target_address;
    uint8_t hotpatch_data[HP_APPLICATOR_DATA_LENGTH];
};

struct __pack hp_applicator_context {
    uint32_t status;   // current status of the hotpatch application
    struct hp_applicator_context_entry entry; //[HP_APPLICATOR_ENTRY_COUNT];
};

extern __hotpatch_context volatile __attribute__((aligned(4))) struct hp_applicator_context g_applicator_context;

void hp_applicator_reset_context(void);
void hp_applicator_init(void);
void hp_applicator_hotpatch_apply(void);

inline uint32_t __attribute__((always_inline))
hp_applicator_is_hotpatch_scheduled(void) {
    return g_applicator_context.status == HP_APPLCIATOR_CONTEXT_ACTIVE;
}



#endif // HP_APPLICATOR_H_