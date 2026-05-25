#include "hp_slot.h"

__hotpatch_slots
static volatile uint32_t hp_unique_identifier = 1; // must start with greater than 1

__hotpatch_slots
struct hp_slot hotpatch_slots[HP_SLOT_COUNT];


#define HP_SLOT_VALID_ADDR(addr) (((uint32_t)(addr)) >= (uint32_t)&hotpatch_slots && ((uint32_t)(addr)) < ((uint32_t)&hotpatch_slots + sizeof(struct hp_slot) * HP_SLOT_COUNT))

__ramfunc
static enum hp_slot_result
hp_slot_allocate(struct hp_slot **slot) {
    struct hp_slot *current_slot, *found_slot;

    if (slot == NULL) {
        return HP_SLOT_ERROR_INVALID_SLOT_POINTER;
    }

    found_slot = NULL;
    for (uint32_t i = 0; i < HP_SLOT_COUNT; i++) {
        current_slot = &hotpatch_slots[i];

        if (hotpatch_slots[i].status == HP_SLOT_STATUS_INACTIVE) {
            current_slot->status = HP_SLOT_STATUS_PENDING;
            found_slot = current_slot;
            break;
        } 
    }

    if (found_slot == NULL) {
        return HP_SLOT_ERROR_NO_FREE_SLOT;
    }

    *slot = found_slot;

    return HP_SLOT_SUCCESS;
}

/**
 * 
 */
__ramfunc
static void
hp_slot_free(struct hp_slot *slot) {
    slot->status = HP_SLOT_STATUS_BLOCKED;
    slot->header.target_address = 0;
    slot->header.code_size = 0;

    hp_code_free(slot->header.code_ptr);

    slot->header.code_ptr = 0;

    slot->status = HP_SLOT_STATUS_INACTIVE;
}

__ramfunc
void
hp_slot_init(void) {
    for (uint32_t i = 0; i < HP_SLOT_COUNT; i++) {
        hotpatch_slots[i].header.code_ptr = NULL;
        hotpatch_slots[i].header.code_size = 0;
        hotpatch_slots[i].header.target_address = 0;
        hotpatch_slots[i].header.type = 0;
        hotpatch_slots[i].identifier = 0;
        hotpatch_slots[i].status = HP_SLOT_STATUS_INACTIVE;
    }

    hp_unique_identifier = 1;
}

/**
 * 
 */
__ramfunc
uint32_t
hp_slot_is_duplicate_target_address(uint32_t target_address) {

    for (uint32_t i = 0; i < HP_SLOT_COUNT; i++) {
        if (hotpatch_slots[i].header.target_address == target_address) {
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * 
 */
__ramfunc
enum hp_slot_result 
hp_slot_add_hotpatch(const struct hp_header *header, const uint8_t *code_ptr, uint32_t *identifier) {
    enum hp_slot_result result;
    uint8_t *code;
    struct hp_slot *slot;

    if (header == NULL) {
        DEBUG_LOG("[error]: hotpatch header is null\r\n");
        return HP_SLOT_ERROR_INVALID_HOTPATCH_HEADER;
    }

    if (code_ptr == NULL) {
        DEBUG_LOG("[error]: hotpatch code is null\r\n");
        return HP_SLOT_ERROR_INVALID_HOTPATCH_CODE;
    }

    if (identifier == NULL) {
        DEBUG_LOG("[error]: identifier is null\r\n");
        return HP_SLOT_ERROR_IVNALID_IDENTIFIER_POINTER;
    }
    // check if the hotpatch already exists
    if (hp_slot_is_duplicate_target_address(header->target_address)) {
        DEBUG_LOG("[error]: hotpatch target address already exists 0x%08X\r\n", header->target_address);
        return HP_SLOT_ERROR_TARGET_ADDRESS_DUPLICATE;
    }

    // allocate a free hotpatch code region
    code = hp_code_allocate(header->code_size);
    if (code == NULL) {
        DEBUG_LOG("[error]: failed to allocate memory for hotpatch code\r\n");
        return HP_SLOT_ERROR_NO_FREE_CODE;
    }

    // allocate a free hotpatch slot
    slot = NULL;
    result = hp_slot_allocate(&slot);
    if (result != HP_SLOT_SUCCESS && slot != NULL) {
        // there was no free slot
        DEBUG_LOG("[error]: failed to allocate memory for hotpatch slot\r\n");
        hp_code_free(code);
        return HP_SLOT_ERROR_NO_FREE_SLOT;
    }

    // copy the meta information of the hotpatch to the slot header
    memcpy((uint8_t *)(&slot->header), (uint8_t *)header, sizeof(struct hp_header));
    
    // update the code pointer and copy the code
    slot->header.code_ptr = code;
    memcpy(slot->header.code_ptr, code_ptr, slot->header.code_size);
    //DEBUG_LOG("CODE: %08X\r\n", slot->header.code_ptr);

    // add the identifier
    slot->identifier = hp_unique_identifier;
    *identifier = hp_unique_identifier;
    hp_unique_identifier++;

    // set the hotpatch slot to pending
    slot->status = HP_SLOT_STATUS_PENDING;

    return HP_SLOT_SUCCESS;
}

__ramfunc
enum hp_slot_result 
hp_slot_remove_hotpatch(struct hp_slot *slot) {
    uint32_t slot_offset;
    struct hp_slot *current_slot;

    // verify that the slot is in range
    if (!HP_SLOT_VALID_ADDR(slot)) {
        return HP_SLOT_ERROR_INVALID_SLOT_POINTER;
    }

    // verify that it is a multiple of slot size
    slot_offset = (uint32_t)slot - (uint32_t)HP_SLOT_START;
    if (slot_offset % (sizeof(struct hp_slot)) != 0) {
        return HP_SLOT_ERROR_INVALID_SLOT_POINTER;
    }

    for (uint32_t i = 0; i < HP_SLOT_COUNT; i++) {
        current_slot = &hotpatch_slots[i];

        if (current_slot == slot) {
            hp_slot_free(current_slot);
            return HP_SLOT_SUCCESS;
        }

    }

    return HP_SLOT_ERROR_INVALID_SLOT_POINTER;
}

/**
 * 
 */
__ramfunc
enum hp_slot_result
hp_slot_get_hotpatch_slot_by_target_address(uint32_t target_address, struct hp_slot **slot) {
    struct hp_slot *current_slot;

    if (slot == NULL) {
        return HP_SLOT_ERROR_INVALID_SLOT_POINTER;
    }

    for (uint32_t i = 0; i < HP_SLOT_COUNT; i++) {
        current_slot = &hotpatch_slots[i];

        if (current_slot->header.target_address != target_address) {
            continue;
        }

        *slot = current_slot;
        return HP_SLOT_SUCCESS;
    }

    return HP_SLOT_ERROR_TARGET_ADDRESS_NOT_FOUND;
}

__ramfunc
enum hp_slot_result 
hp_slot_get_next_pending_hotpatch(struct hp_slot **slot) {
    struct hp_slot *tmp_slot;

    // verify that this is not a null pointer
    if (slot == NULL) {
        return HP_SLOT_ERROR_INVALID_SLOT_POINTER;
    }

    tmp_slot = NULL;
    for (uint32_t i = 0; i < HP_SLOT_COUNT; i++) {
        tmp_slot = &hotpatch_slots[i];

        if ((uint32_t)tmp_slot < HP_SLOT_START + sizeof(uint32_t) || (uint32_t)tmp_slot >= HP_SLOT_END) {
            return HP_SLOT_ERROR_INVALID_SLOT_POINTER;
        }

        if (tmp_slot->status == HP_SLOT_STATUS_PENDING) {
            *slot = tmp_slot;
            return HP_SLOT_SUCCESS;
        }
    }
    return HP_SLOT_ERROR_NO_PENDING_HOTPATCH;
}


__ramfunc
enum hp_slot_result
hp_slot_get(uint32_t identifier, struct hp_slot **slot) {
    struct hp_slot *tmp_slot;

    // verify that this is not a null pointer
    if (slot == NULL) {
        return HP_SLOT_ERROR_INVALID_SLOT_POINTER;
    }

    tmp_slot = NULL;
    for (uint32_t i = 0; i < HP_SLOT_COUNT; i++) {
        tmp_slot = &hotpatch_slots[i];
        if (!HP_SLOT_VALID_ADDR(tmp_slot)) {
            return HP_SLOT_ERROR_INVALID_SLOT_POINTER;
        }

        if (tmp_slot->identifier == identifier) {
            *slot = tmp_slot;

            return HP_SLOT_SUCCESS;
        }
    }
    return HP_SLOT_ERROR_NO_PENDING_HOTPATCH;
}

__ramfunc
enum hp_slot_result 
hp_slot_update_status(uint32_t identifier, enum hp_slot_status status) {
    struct hp_slot *slot;

    if (status >= HP_SLOT_STATUS_MAX) {
        return HP_SLOT_ERROR_INVALID_STATUS;
    }

    for (uint32_t i = 0; i < HP_SLOT_COUNT; i++) {
        slot = &hotpatch_slots[i];

        if (!HP_SLOT_VALID_ADDR(slot)) {
            return HP_SLOT_ERROR_INVALID_SLOT_POINTER;
        }

        if (slot->identifier == identifier) {
            slot->status = status;
            return HP_SLOT_SUCCESS;
        }
    }

    return HP_SLOT_ERROR_SLOT_NOT_FOUND;
}

__ramfunc
uint32_t
hp_slot_get_free_slot_count(void) {
    uint32_t count = 0;

    for (uint32_t i = 0; i < HP_SLOT_COUNT; i++) {
        if (hotpatch_slots[i].status != HP_SLOT_STATUS_INACTIVE) {
            count++;
        }
    }

    return HP_SLOT_COUNT - count;
}