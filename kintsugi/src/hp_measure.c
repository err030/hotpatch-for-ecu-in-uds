#include "hp_measure.h"

#if defined(HP_MEASURE_NUM_ITERATIONS)

uint32_t hp_measure_list[HP_MEASURE_NUM_ITERATIONS];
uint32_t hp_measure_index = 0;
uint32_t hp_measure_time_start = 0;
uint32_t hp_measure_time_end = 0;

#endif