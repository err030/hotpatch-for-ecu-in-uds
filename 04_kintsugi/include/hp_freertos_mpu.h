#ifndef HP_FREERTOS_MPU_H_
#define HP_FREERTOS_MPU_H_
#include <stdint.h>

#include "hp_port.h"

void hp_mpu_init(void);
void hp_mpu_setup_region(uint32_t region, uint32_t start, uint32_t size, uint32_t ap);

#endif // HP_MPU_H_