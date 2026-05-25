#ifndef HP_CONFIG_H_
#define HP_CONFIG_H_

#include "hp_def.h"

#define HP_CONFIG_FREERTOS  1
#define HP_CONFIG_LOG       1

#define HP_SLOT_COUNT           10
#define HP_MAX_CODE_SIZE        64

#if (HP_PERFORMANCE_MEASURE == 1)
#define HP_APPLICATOR_ENTRY_COUNT   HP_MEASURE_NUM_HOTPATCHES
#else
#define HP_APPLICATOR_ENTRY_COUNT   5
#endif

// memory configuartions
#define HP_CODE_MEMORY_SIZE         (HP_SLOT_COUNT * HP_MAX_CODE_SIZE)
#define HP_CODE_MEMORY_MAX_ALLOC    (HP_MAX_CODE_SIZE)

// frequency of the board (in MHz)
#define HP_BOARD_FREQUENCY_NRF52    64
#define HP_BOARD_FREQUENCY          HP_BOARD_FREQUENCY_NRF52

#define HP_SECURITY_EVALUATION      1

#endif // HP_CONFIG_H_