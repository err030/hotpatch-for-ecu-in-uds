#include "hp_guard.h"

#define NO_ACCESS       0x0
#define NO_ACCESS_Msk   ((NO_ACCESS << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk)
/* Privileged No Access, Unprivileged No Access */
#define P_NA_U_NA       0x0
#define P_NA_U_NA_Msk   ((P_NA_U_NA << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk)
/* Privileged Read Write, Unprivileged No Access */
#define P_RW_U_NA       0x1
#define P_RW_U_NA_Msk   ((P_RW_U_NA << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk)
/* Privileged Read Write, Unprivileged Read Only */
#define P_RW_U_RO       0x2
#define P_RW_U_RO_Msk   ((P_RW_U_RO << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk)
/* Privileged Read Write, Unprivileged Read Write */
#define P_RW_U_RW       0x3U
#define P_RW_U_RW_Msk   ((P_RW_U_RW << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk)
/* Privileged Read Write, Unprivileged Read Write */
#define FULL_ACCESS     0x3
#define FULL_ACCESS_Msk ((FULL_ACCESS << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk)
/* Privileged Read Only, Unprivileged No Access */
#define P_RO_U_NA       0x5
#define P_RO_U_NA_Msk   ((P_RO_U_NA << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk)
/* Privileged Read Only, Unprivileged Read Only */
#define P_RO_U_RO       0x6
#define P_RO_U_RO_Msk   ((P_RO_U_RO << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk)
/* Privileged Read Only, Unprivileged Read Only */
#define RO              0x7
#define RO_Msk          ((RO << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk)

#define NOT_EXEC MPU_RASR_XN_Msk

// ==========================


// ==========================

struct __pack hp_guard_region {
	uint32_t region_id;
	uint32_t region_start;
	uint32_t region_size;
	uint32_t permission_active;
	uint32_t permission_inactive;
};

const struct hp_guard_region hp_guard_region_hp_context = {
	.region_id = HP_GUARD_REGION_ID_CONTEXT,
	.region_start = (uint32_t)&__hotpatch_context_start,
	.region_size = (uint32_t)&__hotpatch_context_size,
	.permission_active = P_RW_U_RW_Msk | NOT_EXEC,
	.permission_inactive = P_RO_U_RO_Msk | NOT_EXEC
};

const struct hp_guard_region hp_guard_region_hp_slots = {
	.region_id = HP_GUARD_REGION_ID_SLOTS,
	.region_start = (uint32_t)&__hotpatch_slots_quarantine_start,
	.region_size = (uint32_t)&__hotpatch_slots_quarantine_size,
	.permission_active = P_RW_U_RW_Msk | NOT_EXEC,
	.permission_inactive = P_RO_U_RO_Msk | NOT_EXEC
};

const struct hp_guard_region hp_guard_region_hp_code = {
	.region_id = HP_GUARD_REGION_ID_CODE,
	.region_start = (uint32_t)&__hotpatch_code_start,
	.region_size = (uint32_t)&__hotpatch_code_size,
	.permission_active = P_RW_U_RW_Msk,
	.permission_inactive = P_RO_U_RO_Msk
};

const struct hp_guard_region hp_guard_region_firmware = {
	.region_id = HP_GUARD_REGION_ID_FIRMWARE,
	.region_start = (uint32_t)&__ramfunc_start,
	.region_size = (uint32_t)&__ramfunc_size,
	.permission_active = P_RW_U_RW_Msk,
	.permission_inactive = P_RO_U_RO_Msk
};

#define MPU_REGION_DEF(permissions, size)	((permissions) \
											| ((1 << MPU_RASR_TEX_Pos) | MPU_RASR_C_Msk | MPU_RASR_B_Msk) \
											| ((32 - __builtin_clz(size) - 2) << MPU_RASR_SIZE_Pos) & MPU_RASR_SIZE_Msk)


// ==========================

static inline
void
__attribute__((always_inline))
hp_guard_grant_access(const struct hp_guard_region *region) {
	MPU->RBAR = (region->region_start & MPU_RBAR_ADDR_Msk)
				| MPU_RBAR_VALID_Msk
				| region->region_id;

	MPU->RASR = (region->permission_active)
				| ((1 << MPU_RASR_TEX_Pos) | MPU_RASR_C_Msk | MPU_RASR_B_Msk) 
				| (((32 - __builtin_clz(region->region_size) - 2) << MPU_RASR_SIZE_Pos) & MPU_RASR_SIZE_Msk)
				| MPU_RASR_ENABLE_Msk;
}

static inline
void
__attribute__((always_inline))
hp_guard_revoke_access(const struct hp_guard_region *region) {

	MPU->RBAR = (region->region_start & MPU_RBAR_ADDR_Msk)
				| MPU_RBAR_VALID_Msk 
				| region->region_id;

	MPU->RASR = ((region->permission_inactive)
				| (((1 << MPU_RASR_TEX_Pos) | MPU_RASR_C_Msk) | MPU_RASR_B_Msk) 
				| (((32 - __builtin_clz(region->region_size) - 2) << MPU_RASR_SIZE_Pos) & MPU_RASR_SIZE_Msk)
				| MPU_RASR_ENABLE_Msk);
}


static inline uint8_t hp_mpu_region_count(void) {
	return (uint8_t)( (MPU->TYPE & MPU_TYPE_DREGION_Msk) >> MPU_TYPE_DREGION_Pos );
}
/*
static inline void
hp_guard_dump_mpu_region(uint32_t index) {
	MPU->RNR = index;

	uint32_t base, size, perm;

	base = (MPU->RBAR & MPU_RBAR_ADDR_Msk);
	size = (MPU->RASR & MPU_RASR_SIZE_Msk) >> MPU_RASR_SIZE_Pos;
	perm = (MPU->RASR & MPU_RASR_AP_Msk) >> MPU_RASR_AP_Pos;
	DEBUG_LOG("[%d], %d: RBAR: %08X, RASR: %08X, (%08X:%08X:%08X:%08X)\n", index, MPU_RBAR_ADDR_Pos, MPU->RBAR, MPU->RASR, base, size, 1 << (size + 1), perm);
}
*/

void
__ramfunc
//__attribute__((optimize("O3")))
hp_guard_applicator(uint32_t task_manager_next, uint32_t task_manager_prev) {
	// next task is manager
	if (task_manager_next) {
		//MPU->CTRL &= ~MPU_CTRL_ENABLE_Msk;
        hp_guard_grant_access(&hp_guard_region_hp_context);
		if (hp_applicator_is_hotpatch_scheduled()) {
			hp_guard_grant_access(&hp_guard_region_firmware);
			//MPU->CTRL |= MPU_CTRL_ENABLE_Msk | MPU_CTRL_PRIVDEFENA_Msk;
			hp_guard_synch_access();
			
			hp_applicator_hotpatch_apply();

			//MPU->CTRL &= ~MPU_CTRL_ENABLE_Msk;
			hp_guard_revoke_access(&hp_guard_region_firmware);
		}

        hp_guard_grant_access(&hp_guard_region_hp_slots);
        hp_guard_grant_access(&hp_guard_region_hp_code);

		//MPU->CTRL |= MPU_CTRL_ENABLE_Msk | MPU_CTRL_PRIVDEFENA_Msk;
		hp_guard_synch_access();
	} else if (task_manager_prev) {
			//MPU->CTRL &= ~MPU_CTRL_ENABLE_Msk;

		hp_guard_revoke_access(&hp_guard_region_hp_context);
		hp_guard_revoke_access(&hp_guard_region_hp_slots);
		hp_guard_revoke_access(&hp_guard_region_hp_code);

		//MPU->CTRL |= MPU_CTRL_ENABLE_Msk | MPU_CTRL_PRIVDEFENA_Msk;
		hp_guard_synch_access();
	}
}


  ///////////////////////////////////////////////////////////////////
 //             FUNCTIONS FOR MEASUREMENTS BELOW                  //
///////////////////////////////////////////////////////////////////

#if (HP_PERFORMANCE_MEASURE == 1 && (HP_PERFORMANCE_MEASURE_CONTEXT_SWITCH == 1 || HP_PERFORMANCE_MEASURE_APPLICATOR == 1))
#include "hp_guard.h"
void
__ramfunc
__attribute__((optimized("O0")))
hp_applicator_setup_measurement(uint32_t address) {
    
    const uint8_t hp_data[HP_APPLICATOR_DATA_LENGTH] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    
    /*if (num > HP_APPLICATOR_ENTRY_COUNT) {
        DEBUG_LOG("[error]: requested number exceeds applicator entry count max\r\n");
        return;
    }*/
    // enable access to applicator context

    hp_guard_grant_access(&hp_guard_region_hp_context);
    hp_guard_synch_access();

	g_applicator_context.entry.target_address = address;

	for (uint32_t i = 0; i < HP_APPLICATOR_DATA_LENGTH; i++) {
		g_applicator_context.entry.hotpatch_data[i] = hp_data[i];
	}

	g_applicator_context.status = HP_APPLCIATOR_CONTEXT_ACTIVE;


    hp_guard_revoke_access(&hp_guard_region_hp_context);
    hp_guard_synch_access();
}

void
hp_guard_revoke_all_access(void) {
	hp_guard_revoke_access(&hp_guard_region_hp_context);
	hp_guard_revoke_access(&hp_guard_region_hp_slots);
	hp_guard_revoke_access(&hp_guard_region_hp_code);
	hp_guard_revoke_access(&hp_guard_region_firmware);
	hp_guard_synch_access();
}
#else
void hp_applicator_setup_measurement(uint32_t num, uint32_t address) {
    // empty 
}
#endif
