#include "hp_freertos_mpu.h"

struct mpu_region {
	uint32_t region;
	uint32_t start;
	uint32_t size;
	uint32_t ap;
};

#define MPU_REGION_COUNT    4
#define P_RO_U_RO           0x6
#define P_RO_U_RO_Msk       ((P_RO_U_RO << MPU_RASR_AP_Pos) & MPU_RASR_AP_Msk)

struct mpu_region mpu_region_defs[MPU_REGION_COUNT] = {
	// region 0: ramfunc (execute in RAM) - make RO for others
	{
		.region = 0,
		.start  = (uint32_t)&__ramfunc_start,
		.size   = (uint32_t)&__ramfunc_size,
		.ap     = P_RO_U_RO_Msk | ((1 << MPU_RASR_TEX_Pos) | MPU_RASR_C_Msk | MPU_RASR_B_Msk)
	},
	// region 1: hotpatch code region (make read-only)
	{
		.region = 1,
		.start  = (uint32_t)HP_CODE_START,
		.size   = (uint32_t)HP_CODE_SIZE,
		.ap     = P_RO_U_RO_Msk | ((1 << MPU_RASR_TEX_Pos) | MPU_RASR_C_Msk | MPU_RASR_B_Msk)
	},
	// region 2: hotpatch slots region (make read-only)
	{
		.region = 2,
		.start  = (uint32_t)HP_SLOT_START,
		.size   = (uint32_t)HP_SLOT_SIZE,
		.ap     = P_RO_U_RO_Msk | ((1 << MPU_RASR_TEX_Pos) | MPU_RASR_C_Msk | MPU_RASR_B_Msk)
	},
	// region 3: hotpatch context region (make read-only)
	{
		.region = 3,
		.start  = (uint32_t)HP_CONTEXT_START,
		.size   = (uint32_t)HP_CONTEXT_SIZE,
		.ap     = P_RO_U_RO_Msk | ((1 << MPU_RASR_TEX_Pos) | MPU_RASR_C_Msk | MPU_RASR_B_Msk)
	}
};


void
hp_mpu_init(void) {
	struct mpu_region *def;

	// disable MPU
	MPU->CTRL = 0;

	// clear all regions
	for (uint32_t i = 0; i < 8; i++)
    {
        MPU->RNR    = i;
        MPU->RASR   = 0;
        MPU->RBAR   = 0;
    }
	
    // setup the regions
	def = NULL;
	for (uint32_t i = 0; i < MPU_REGION_COUNT; i++) {
		def = &mpu_region_defs[i];
		hp_mpu_setup_region(def->region, def->start, def->size, def->ap);
	}

    // enable the memory management fault handler
	SCB->SHCSR |= SCB_SHCSR_MEMFAULTENA_Msk;
	
    // enable the MPU
	MPU->CTRL = (1 << MPU_CTRL_ENABLE_Pos) | MPU_CTRL_PRIVDEFENA_Msk;

	__ISB();
	__DSB();	
}

void
hp_mpu_setup_region(uint32_t region, uint32_t start, uint32_t size, uint32_t ap) {
	// setup an MPU region
	MPU->RNR = region;
	
	MPU->RBAR = (start & MPU_RBAR_ADDR_Msk)
				| MPU_RBAR_VALID_Msk | region;

	MPU->RASR = ((ap))
			   	| (((32 - __builtin_clz(size - 1) - 2 + 1) << MPU_RASR_SIZE_Pos) & MPU_RASR_SIZE_Msk)
				| MPU_RASR_ENABLE_Msk;
				
	__ISB();
	__DSB();
}