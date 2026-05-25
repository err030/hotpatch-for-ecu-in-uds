#ifndef HP_GUARD_H_
#define HP_GUARD_H_

#include "hp_def.h"
#include "hp_config.h"
#include "hp_port.h"

#include "hp_applicator.h"

#define HP_GUARD_LOWEST_PRIORITY    1

enum hp_guard_region_ids {
	HP_GUARD_REGION_ID_CODE = 4,
	HP_GUARD_REGION_ID_FIRMWARE,
	HP_GUARD_REGION_ID_CONTEXT,
	HP_GUARD_REGION_ID_SLOTS,
};

enum hp_guard_result {
    HP_GUARD_SUCCESS = 0
};

void hp_guard_applicator(uint32_t task_manager_next, uint32_t task_manager_prev);

inline
void 
__attribute__((always_inline))
hp_guard_synch_access(void) {
	__asm__ volatile("dsb\n"
					 "isb\n");
}

inline void
__attribute__((always_inline))
hp_guard_mpu_disable(void) {
	MPU->CTRL &= ~MPU_CTRL_ENABLE_Msk;
	hp_guard_synch_access();
}

inline void
__attribute__((always_inline))
hp_guard_mpu_enable(void) {
	MPU->CTRL = MPU_CTRL_ENABLE_Msk | MPU_CTRL_PRIVDEFENA_Msk;
	hp_guard_synch_access();
}

#if (HP_PERFORMANCE_MEASURE == 1 && (HP_PERFORMANCE_MEASURE_CONTEXT_SWITCH == 1 || HP_PERFORMANCE_MEASURE_APPLICATOR == 1))
  ///////////////////////////////////////////////////////////////////
 //             FUNCTIONS FOR MEASUREMENTS BELOW                  //
///////////////////////////////////////////////////////////////////

void hp_applicator_setup_measurement(uint32_t address);
void hp_guard_revoke_all_access(void);
#endif

#endif // HP_GUARD_H_