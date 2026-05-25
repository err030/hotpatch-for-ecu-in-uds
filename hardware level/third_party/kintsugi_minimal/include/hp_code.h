#ifndef HP_CODE_H_
#define HP_CODE_H_

#include "hp_def.h"
#include "hp_port.h"
#include "hp_config.h"

void hp_code_init(void);
void *hp_code_allocate(uint32_t size);
void  hp_code_free(void *ptr);

#endif // HP_CODE_H_