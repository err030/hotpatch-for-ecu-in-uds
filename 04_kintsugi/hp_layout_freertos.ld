SECTIONS
{
    .hotpatch_context :
    {
        . = ALIGN(32);
        . = ALIGN(1 << LOG2CEIL(__hotpatch_context_size));
        __hotpatch_context_start = .;

        KEEP(*(.hotpatch_context*));

        . = ALIGN(32);
        . = ALIGN(1 << LOG2CEIL(__hotpatch_context_size));

        __hotpatch_context_end = .;
    }  > RAM

    __hotpatch_context_size = __hotpatch_context_end - __hotpatch_context_start;
}

SECTIONS
{
    . = ALIGN(32);
    . = ALIGN(1 << LOG2CEIL(__hotpatch_slots_quarantine_size));
    __hotpatch_slots_quarantine_start = .;

    .hotpatch_slots :
    {

        __hotpatch_slots_start = .;

        *(.hotpatch_slots*);

        __hotpatch_slots_end = .;
    } > RAM

    .hotpatch_quarantine :
    {
        __hotpatch_quarantine_start = .;

        KEEP(*(.hotpatch_quarantine*));

        __hotpatch_quarantine_end = .;
    } > RAM
    
    . = ALIGN(32);
    . = ALIGN(1 << LOG2CEIL(__hotpatch_slots_quarantine_size) + 1);
    __hotpatch_slots_quarantine_end = .;

    __hotpatch_slots_size = __hotpatch_slots_end - __hotpatch_slots_start;
    __hotpatch_quarantine_size = __hotpatch_quarantine_end - __hotpatch_quarantine_start;
    __hotpatch_slots_quarantine_size = __hotpatch_slots_quarantine_end - __hotpatch_slots_quarantine_start;
}

SECTIONS
{

    .hotpatch_code :
    {
        . = ALIGN(32);
        . = ALIGN(1 << LOG2CEIL(__hotpatch_code_size));

        __hotpatch_code_start = .;
        KEEP(*(.hotpatch_code*));

        . = ALIGN(32);
        . = ALIGN(1 << LOG2CEIL(__hotpatch_code_size));
        __hotpatch_code_end = .;
    } > RAM

    __hotpatch_code_size = __hotpatch_code_end - __hotpatch_code_start;
}

SECTIONS
{
    .ramfunc : 
    {
        . = ALIGN(32);
        . = ALIGN((1 << LOG2CEIL(__ramfunc_size)));

        
        __ramfunc_start = .;

        KEEP(*(.ramfunc*));
            
        . = ALIGN(32);
        . = ALIGN((1 << LOG2CEIL(__ramfunc_size)));

        __ramfunc_end = .;
    } > RAM AT > RAM
    
    __ramfunc_size = __ramfunc_end - __ramfunc_start;
    __ramfunc_load_start = LOADADDR(.ramfunc);
}