#include "hp_manager.h"
#include "hp_slot.h"
#include "hp_code.h"
#include "hp_applicator.h"
#include "hp_guard.h"

#if (HP_CONFIG_FREERTOS == 1)
uint32_t UART_PRINT_FLAG = 0;
#endif

#define HP_PATCHABLE_MEMORY_REGION_COUNT 1
static const struct hp_memory_region hp_patchable_memory_regions[HP_PATCHABLE_MEMORY_REGION_COUNT] = {
    { HP_RAMFUNC_START, HP_RAMFUNC_END }
};

__hotpatch_quarantine
uint8_t hp_quarantine_memory[HP_QUARANTINE_ENTRY_SIZE] = { 0 };

__ramfunc
uint32_t
hp_manager_valid_target_address(uint32_t address) {
    
    for (uint32_t i = 0; i < HP_PATCHABLE_MEMORY_REGION_COUNT; i++) {
        if (address >= hp_patchable_memory_regions[i].start_address &&
            address < (hp_patchable_memory_regions[i].end_address)) {
            
            return TRUE;
        }
    }

    return FALSE;
}

__ramfunc
uint32_t 
hp_manager_valid_quarantine_address(uint32_t address) {
    return address >= HP_QUARANTINE_START && address < HP_QUARANTINE_END;
}

__ramfunc
enum hp_manager_result
hp_manager_validate_hotpatch(const uint8_t *data, uint32_t size) {

    struct hp_header *header;

    if (data == NULL) {
        DEBUG_LOG("[error]: hotpatch data pointer is invalid\r\n");
        return HP_MANAGER_ERROR_INVALID_DATA_PTR;
    }

    if (hp_manager_valid_quarantine_address((uint32_t)data) != TRUE) {
        DEBUG_LOG("[error]: hotpatch data pointer not in quarantine region\r\n");
        return HP_MANAGER_ERROR_DATA_PTR_OUTSIDE_QUARANTINE;
    }

    if (size > (sizeof(struct hp_header) + HP_MAX_CODE_SIZE)) {
        DEBUG_LOG("[error]: hotpatch size exceeds maximum allowed size\r\n");
        return HP_MANAGER_ERROR_INVALID_SIZE;
    }

    // sanity checking
    header = (struct hp_header *)(data);

    // check if the type is valid
    if (hp_valid_type(header->type) != TRUE) {
        DEBUG_LOG("[error]: invalid hotpatch type %d\r\n", header->type);
        return HP_MANAGER_ERROR_INVALID_TYPE;
    }

    // verify that the target address is valid
    if (hp_manager_valid_target_address(header->target_address) != TRUE) {
        DEBUG_LOG("[error]: target address for hotpatch is invalid\r\n");
        return HP_MANAGER_ERROR_INVALID_TARGET_ADDRESS;
    }

    return HP_MANAGER_SUCCESS;
}

__ramfunc
enum hp_manager_result
hp_manager_process_hotpatch(const uint8_t *data, uint32_t size, uint32_t *identifier) {
    struct hp_header *header;
    enum hp_slot_result slot_result;
    enum hp_manager_result result;
    uint32_t local_identifier;
    uint8_t *code_ptr;

    #if (HP_PERFORMANCE_MEASURE_SUBFUNCTION_VALIDATING == 1)
    hp_measure_start();
    result = hp_manager_validate_hotpatch(data, size);
    hp_measure_stop();
    #else
    result = hp_manager_validate_hotpatch(data, size);
    #endif
    if (result != HP_MANAGER_SUCCESS) {
        return result;
    }

    if (hp_slot_get_free_slot_count() == 0) {
        DEBUG_LOG("[error]: no free slots for the hotpatch\r\n");
        return HP_MANAGER_ERROR_NO_FREE_SLOTS;
    }

    // get the hotpatch header
    header = (struct hp_header *)(data);

    // compute the code ptr
    code_ptr = (uint8_t *)(data + sizeof(struct hp_header));

    // add the hotpatch to a slot
    #if (HP_PERFORMANCE_MEASURE_SUBFUNCTION_STORING == 1)
    hp_measure_start();
    slot_result = hp_slot_add_hotpatch(header, code_ptr, &local_identifier);
    hp_measure_stop();
    #else
    slot_result = hp_slot_add_hotpatch(header, code_ptr, &local_identifier);
    #endif

    if (slot_result != HP_SLOT_SUCCESS) {
        DEBUG_LOG("[error]: unable to add hotpatch to a free slot\r\n");
        return HP_MANAGER_ERROR_SLOT_FAILED;
    }

    *identifier = local_identifier;

    return HP_MANAGER_SUCCESS;
}

__ramfunc
enum hp_manager_result
hp_manager_schedule_hotpatch(uint32_t identifier) {
    enum hp_slot_result slot_result;
    struct hp_slot *slot;
    uint32_t alignment, i;

    // check whether or not a hotpatch is pending for application
    if (hp_applicator_is_hotpatch_scheduled() == TRUE) {
        DEBUG_LOG("[info]: patch already scheduled\r\n");
        return HP_MANAGER_ERROR_HOTPATCH_APPLICATION_PENDING;
    }

    // get the next ready hotpatch slot
    slot_result = hp_slot_get(identifier, &slot);
    if (slot_result != HP_SLOT_SUCCESS) {
        DEBUG_LOG("[error]: was not able to get next pending hotpatch\r\n");
        return HP_MANAGER_ERROR_NO_PENDING_HOTPATCH;
    }

    // verify that the hotpatch is pending
    if (slot->status != HP_SLOT_STATUS_PENDING) {
        DEBUG_LOG("[error]: hotpatch is not pending\r\n");
        return HP_MANAGER_ERROR_INVALID_PENDING_HOTPATCH;
    }

    g_applicator_context.entry.target_address = slot->header.target_address;

    if (slot->header.type == HP_TYPE_REDIRECT) {
        // write a trampoline to the data
        alignment =  (slot->header.target_address & 0b10) << 16;
        *(uint32_t *)((uint32_t)&g_applicator_context.entry.hotpatch_data + 0) = 0xF000F8DF | alignment;
        *(uint32_t *)((uint32_t)&g_applicator_context.entry.hotpatch_data + 4) = (uint32_t)(slot->header.code_ptr) | 1;
    } else if (slot->header.type == HP_TYPE_REPLACEMENT) {

        if (slot->header.code_size > HP_APPLICATOR_DATA_LENGTH) {
            DEBUG_LOG("[error]: invalid slot code data length\r\n");
            g_applicator_context.entry.target_address = 0;
            return HP_MANAGER_ERROR_DATA_SIZE_MISMATCH;
        }

        // write the actual code to the data
        for (i = 0; i < slot->header.code_size; i++) {
            g_applicator_context.entry.hotpatch_data[i] = *(uint8_t *)(slot->header.code_ptr + i);
        }

        // fill the remainder with the current data
        for (; i < HP_APPLICATOR_DATA_LENGTH; i++) {
            g_applicator_context.entry.hotpatch_data[i] = *(uint8_t *)(slot->header.target_address + i);
        }
    }

    // set the slot to scheduled
    slot->status = HP_SLOT_STATUS_SCHEDULED;

    // finally, update the status such that the hotpatch can be applied by the applicator
    g_applicator_context.status = HP_APPLCIATOR_CONTEXT_ACTIVE;

    return HP_MANAGER_SUCCESS;
}

__ramfunc
enum hp_manager_result
hp_manager(const uint8_t *data, uint32_t size, uint32_t *identifier) {
    enum hp_manager_result manager_result;
    enum hp_slot_result slot_result;

    uint32_t local_identifier;
    struct hp_slot *slot;

    if (size > (HP_MAX_CODE_SIZE + sizeof(struct hp_header))) {
        DEBUG_LOG("[error]: size of hotpatch exceeds quarantine size.\r\n");
        return HP_MANAGER_ERROR_INVALID_SIZE;
    }

    // copy hotpatch to quarantine
    memcpy(hp_quarantine_memory, data, size);

    manager_result = hp_manager_process_hotpatch(hp_quarantine_memory, size, &local_identifier);
    if (manager_result != HP_MANAGER_SUCCESS) {
        DEBUG_LOG("[error]: could not parse hotpatch: %lu\r\n", manager_result);
        return manager_result;
    }

    // delete the quarantine version
    memset(hp_quarantine_memory, 0, size);

#if (HP_PERFORMANCE_MEASURE_SUBFUNCTION_SCHEDULING == 1)
    hp_measure_start();
    manager_result = hp_manager_schedule_hotpatch(local_identifier);
    hp_measure_stop();
#else
    manager_result = hp_manager_schedule_hotpatch(local_identifier);
#endif

    if (manager_result != HP_MANAGER_SUCCESS) {
        DEBUG_LOG("[error]: could not schedule hotpatch: %lu\r\n", manager_result);
        return manager_result;
    }


#if (HP_PERFORMANCE_MEASURE_MANAGER == 1 && HP_PERFORMANCE_MEASURE_MICRO == 1)

    slot->status = HP_SLOT_STATUS_ACTIVE;
    *identifier = local_identifier;

    return HP_MANAGER_SUCCESS;
#endif


#if (HP_MEASURE_FRAMEWORK == 1)
    do {
        vTaskDelay(1);
    } while (hp_applicator_is_hotpatch_scheduled());
#else
    do {
        #if (HP_CONFIG_FREERTOS == 1)
            vTaskDelay(1000);
        #elif (HP_CONFIG_ZEPHYROS == 1)
            k_sleep(K_MSEC(50));
        #endif
    } while (hp_applicator_is_hotpatch_scheduled());
#endif
    // update the status of the hoptatch slot to applied
    slot_result = hp_slot_get(local_identifier, &slot);
    if (slot_result != HP_SLOT_SUCCESS) {
        DEBUG_LOG("[error]: could not retrieve hotpatch slot\r\n");
        return HP_MANAGER_ERROR_INVALID_IDENTIFIER;
    }

    slot->status = HP_SLOT_STATUS_ACTIVE;

    *identifier = local_identifier;


    return HP_MANAGER_SUCCESS;
}

#if (HP_TARGET_CRAZYFLY == 1)
#include "static_mem.h"
STATIC_MEM_TASK_ALLOC_STACK_NO_DMA_CCM_SAFE(hp_manager_task, (512));
#endif

void hp_manager_init(void) {

    hp_slot_init();
    hp_code_init();
    hp_applicator_init();

    #if (HP_CONFIG_FREERTOS == 1) 
    
    #if (HP_TARGET_CRAZYFLY == 1)
        STATIC_MEM_TASK_CREATE(hp_manager_task, hp_manager_task, HP_MANAGER_TASK_NAME, NULL, HP_MANAGER_TASK_PRIORITY);
    #endif

    #endif
}
