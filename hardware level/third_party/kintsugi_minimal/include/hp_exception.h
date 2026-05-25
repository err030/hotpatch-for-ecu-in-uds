#ifndef HP_EXCEPTION_H_
#define HP_EXCEPTION_H_

#include "hp_def.h"
#include "hp_port.h"
#include "hp_config.h"
#include "hp_code.h"

//#if (HP_CONFIG_FREERTOS == 1)
void MemManage_Handler(void);
//#endif

#endif