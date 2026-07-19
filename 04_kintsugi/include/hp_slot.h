#ifndef HP_SLOT_H_
#define HP_SLOT_H_

#include "hp_def.h"
#include "hp_port.h"
#include "hp_config.h"
#include "hp_code.h"


enum hp_slot_result {
    HP_SLOT_FAILED = -1,
    HP_SLOT_SUCCESS,
    HP_SLOT_ERROR_NO_FREE_CODE,
    HP_SLOT_ERROR_NO_FREE_SLOT,
    HP_SLOT_ERROR_TARGET_ADDRESS_DUPLICATE,
    HP_SLOT_ERROR_INVALID_HOTPATCH_HEADER,
    HP_SLOT_ERROR_INVALID_HOTPATCH_CODE,
    HP_SLOT_ERROR_IVNALID_IDENTIFIER_POINTER,
    HP_SLOT_ERROR_INVALID_SLOT_POINTER,
    HP_SLOT_ERROR_TARGET_ADDRESS_NOT_FOUND,
    HP_SLOT_ERROR_SLOT_NOT_FOUND,
    HP_SLOT_ERROR_INVALID_STATUS,
    HP_SLOT_ERROR_NO_PENDING_HOTPATCH,
    HP_MANAGER_ERROR_INVALID_PENDING_HOTPATCH,
};

enum hp_slot_status {
    HP_SLOT_STATUS_INACTIVE = 0,   // slot is not in use
    HP_SLOT_STATUS_PENDING,        // slot is pending for application
    HP_SLOT_STATUS_SCHEDULED,      // slot is scheduled for application
    HP_SLOT_STATUS_ACTIVE,         // slot is active (hotpatch has been applied)
    HP_SLOT_STATUS_BLOCKED,         // slot is currently blocked for freeing
    
    HP_SLOT_STATUS_MAX
};

struct __pack hp_slot {
    enum hp_slot_status status; // status of the hotpatch
    uint32_t identifier;        // unique identifier for the hotpatch
    struct hp_header header;    // header of the hotpatch
};

extern struct hp_slot hotpatch_slots[HP_SLOT_COUNT];

void hp_slot_init(void);

enum hp_slot_result hp_slot_add_hotpatch(const struct hp_header *header, const uint8_t *code_ptr, uint32_t *identifier);
enum hp_slot_result hp_slot_remove_hotpatch(struct hp_slot *slot);
enum hp_slot_result hp_slot_get_hotpatch_slot_by_target_address(uint32_t target_address, struct hp_slot **slot);
enum hp_slot_result hp_slot_get_next_pending_hotpatch(struct hp_slot **slot);
enum hp_slot_result hp_slot_get(uint32_t identifier, struct hp_slot **slot);
enum hp_slot_result hp_slot_update_status(uint32_t identifier, enum hp_slot_status status);

uint32_t hp_slot_get_free_slot_count(void);


#endif // HP_SLOT_H_