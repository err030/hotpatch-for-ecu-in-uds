
SECTION_DATA_PROLOGUE(.hotpatch_context,,)
{
    MPU_ALIGN(__hotpatch_context_size);
    __hotpatch_context_start = .;

    KEEP(*(.hotpatch_context*));

    MPU_ALIGN(__hotpatch_context_size);
    __hotpatch_context_end = .;
} GROUP_DATA_LINK_IN(RAMABLE_REGION, ROMABLE_REGION)

__hotpatch_context_size = __hotpatch_context_end - __hotpatch_context_start;
__hotpatch_context_load_start = LOADADDR(.hotpatch_context);

SECTION_DATA_PROLOGUE(.hotpatch_slots_quarantine,,)
{
    MPU_ALIGN(__hotpatch_slots_quarantine_size);

    __hotpatch_slots_quarantine_start = .;


    __hotpatch_slots_start = .;

    *(.hotpatch_slots*);

    __hotpatch_slots_end = .;
    
    . = ALIGN(32);

    __hotpatch_quarantine_start = .;

    KEEP(*(.hotpatch_quarantine*));

    __hotpatch_quarantine_end = .;
 

    MPU_ALIGN(__hotpatch_slots_quarantine_size);
    __hotpatch_slots_quarantine_end = .;

} GROUP_DATA_LINK_IN(RAMABLE_REGION, ROMABLE_REGION)

__hotpatch_slots_size = __hotpatch_slots_end - __hotpatch_slots_start;
__hotpatch_quarantine_size = __hotpatch_quarantine_end - __hotpatch_quarantine_start;
__hotpatch_slots_quarantine_size = __hotpatch_slots_quarantine_end - __hotpatch_slots_quarantine_start;
__hotpatch_slots_quarantine_load_start = LOADADDR(.hotpatch_slots_quarantine);

SECTION_DATA_PROLOGUE(.hotpatch_code,,)
{
    MPU_ALIGN(__hotpatch_code_size);
       
    __hotpatch_code_start = .;
    KEEP(*(.hotpatch_code*));

    MPU_ALIGN(__hotpatch_code_size);
    __hotpatch_code_end = .;
} GROUP_DATA_LINK_IN(RAMABLE_REGION, ROMABLE_REGION)

__hotpatch_code_size = __hotpatch_code_end - __hotpatch_code_start;
__hotpatch_code_load_start = LOADADDR(.hotpatch_code);

