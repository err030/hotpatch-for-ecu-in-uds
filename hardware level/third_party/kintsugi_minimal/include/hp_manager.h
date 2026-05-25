#ifndef HP_MANAGER_H_
#define HP_MANAGER_H_

#include "hp_def.h"
#include "hp_config.h"
#include "hp_port.h"

enum hp_manager_result {
    HP_MANAGER_SUCCESS = 0,
    HP_MANAGER_ERROR_INVALID_DATA_PTR,
    HP_MANAGER_ERROR_DATA_PTR_OUTSIDE_QUARANTINE,
    HP_MANAGER_ERROR_INVALID_SIZE,
    HP_MANAGER_ERROR_CODE_SIZE_MISMATCH,
    HP_MANAGER_ERROR_INVALID_CODE_SIZE,
    HP_MANAGER_ERROR_INVALID_IDENTIFIER_PTR,
    HP_MANAGER_ERROR_INVALID_IDENTIFIER,
    HP_MANAGER_ERROR_DATA_SIZE_MISMATCH,
    HP_MANAGER_ERROR_NO_FREE_SLOTS,
    HP_MANAGER_ERROR_SIZE_MISMATCH,
    HP_MANAGER_ERROR_MAGIC_MISMATCH,
    HP_MANAGER_ERROR_INVALID_TARGET_ADDRESS,
    HP_MANAGER_ERROR_INVALID_TYPE,
    HP_MANAGER_ERROR_SLOT_FAILED,
    HP_MANAGER_ERROR_SLOT_NOT_FOUND,
    HP_MANAGER_ERROR_SLOT_INVALID_STATE,
    HP_MANAGER_ERROR_NO_PENDING_HOTPATCH,
    HP_MANAGER_ERROR_HOTPATCH_APPLICATION_PENDING,
    HP_MANAGER_ERROR_ENTRY_HEADER_SIZE_MISMATCH,
    HP_MANAGER_ERROR_INVALID_CALL_PTR,
    HP_MANAGER_ERROR_VENEER_ALLOCATION_FAILED,
};

struct __pack hp_memory_region {
    uint32_t start_address;
    uint32_t end_address;
};

enum hp_manager_result hp_manager_receive_hotpatch(const uint8_t *data, uint32_t size, uint32_t *identifier);
enum hp_manager_result hp_manager_schedule_hotpatch(uint32_t identifier);
enum hp_manager_result hp_manager(const uint8_t *data, uint32_t size, uint32_t *identifier);

void hp_manager_init(void);
void hp_manager_task(void *user_data);

#endif // HP_MANAGER_H_