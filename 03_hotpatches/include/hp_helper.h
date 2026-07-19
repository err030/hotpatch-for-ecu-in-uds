#include <stdint.h>

#define STRINGIZE(x) #x
#define STRINGIZE_COUNTER(x) STRINGIZE(x)

#define HOTPATCH_FUNC_NAME __func__

#define HOTPATCH_FUNCTION_START(name, offset, type, return_offset) static void __attribute__((used, noinline)) hotpatch_function_##name##_hotpatch_offset_##offset##_hotpatch_type_##type##_hotpatch_return_offset_##return_offset##_hotpatch_end (void)

#define HOTPATCH_FUNCTION_START_NAKED(name, offset, type, return_offset) static void __attribute__((optimize(0), used, naked, noinline, no_instrument_function)) hotpatch_function_##name##_hotpatch_offset_##offset##_hotpatch_type_##type##_hotpatch_return_offset_##return_offset##_hotpatch_end (void)

#define HOTPATCH_EXTRA_FUNCTION_START(return_type, name, ...) static return_type __attribute((noinline)) hotpatch_function_##name##_hotpatch_end (__VA_ARGS__)

#define CALL_HOTPATCH_EXTRA_FUNCTION(name, ...) hotpatch_function_##name##_hotpatch_end (__VA_ARGS__)

#define HOTPATCH_ADDRESS(name) hotpatch_address_##name

#define ADDRESS(name) static volatile uint32_t HOTPATCH_ADDRESS(name)

#define VAR_REG(name, reg, type) register volatile type name __asm(reg)

#define VAR_PTR(name, type) volatile volatile type *name = (volatile type *)(&HOTPATCH_ADDRESS(name))

#define VAR_ADDR(name, type, addr) volatile volatile type *name = (type *)(addr);

#define VAR_REG_PTR(name, reg, type) volatile type name __asm(reg) = (volatile type *)(&HOTPATCH_ADDRESS(name))

#define VAR_MEMORY_REG_PTR(name, reg, offset, type) volatile type *name = ({ register uint32_t r __asm(reg); (type *)(r + offset); })

#define VAR_MEMORY_VALUE(name, type) type name = *(volatile type *)(&HOTPATCH_ADDRESS(name))

#define VAR_ORIG_VALUE(name, type) volatile type **name = (volatile type **)(&HOTPATCH_ADDRESS(name))


#define HOTPATCH_FUNCTION_RETURN()                          \
do {                                                        \
    __asm__ volatile(   "hotpatch_return:\n");              \
    return;                                                 \
} while(0)


#define HOTPATCH_CONCAT_IMPL(x, y)   x##y
#define HOTPATCH_CONCAT(x, y)        HOTPATCH_CONCAT_IMPL(x, y)
#define HOTPATCH_STRINGIFY(x)        #x
#define HOTPATCH_XSTRINGIFY(x)       HOTPATCH_STRINGIFY(x)

#define HOTPATCH_BRANCH_TO_ORIG_LABEL(x)    HOTPATCH_XSTRINGIFY(HOTPATCH_CONCAT(hotpatch_branch_to_orig_, x)) ":"
#define HOTPATCH_BRANCH_TO_ORIGINAL_CODE(x)                         \
do {                                                                \
    __asm__ volatile(   HOTPATCH_BRANCH_TO_ORIG_LABEL(x)            \
                        "nop\n"                                     \
                        "nop\n"                                     \
                        "nop\n"                                     \
                        "nop\n"                                     \
                        "nop\n"                                     \
                        "nop\n"                                     \
    );                                                              \
} while(0);                                                      

#define HOTPATCH_BRANCH_TO_ORIGINAL_CODE_LABEL(x)                   \
do {                                                                \
    __asm__ volatile("b " HOTPATCH_BRANCH_TO_ORIG_LABEL(x));        \
} while(0);

#define HOTPATCH_GOTO_EXIT() __asm__ volatile("b hotpatch_return\n")

#define STORE_REGISTERS(registers) __asm__ volatile("push {"  registers "}\n")

#define RESTORE_REGISTERS(registers) __asm__ volatile("pop {" registers "}\n")

#define READ_STACK(type, offset) ({ type result; register void *sp __asm("sp"); result = *(type *)((uint32_t)(sp) + offset); result;})

#define GET_STACK(offset) ({ uint32_t result; register void *sp __asm("sp"); result = (uint32_t)sp + offset; result; })

#define SKIP_STACK(offset) __asm__ volatile("add sp, %0\n" : : "i" (offset) : "sp");

#define MODIFY_RETURN_VALUE(value) __asm__ volatile("mov r0, %0\n" : : "r" (value) : "r0")

#define GET_RETURN(var) ({ uint32_t result; register uint32_t lr __asm("lr"); result = lr; result; })

#define SET_RETURN(value, ...) __asm__ volatile("mov lr, %0\n" : : "r" (value) : __VA_ARGS__ );

#define ADD_RETURN(value) __asm__ volatile("add lr, lr, %0" : : "i" (value) : "lr");

#define HOTPATCH_RETURN() __asm__ volatile("bx lr\n")

#define SET_RETURN_VALUE(value) __asm__ volatile("mov r0, %0\n" : : "r" ((uint32_t)value) : "r0");

#define ARM_BRANCH_TO_ADDRESS(name)     \
do {                                    \
    __asm__ volatile(                   \
        "push {r0}\n"                   \
        "ldr r0, =%0\n"                 \
        "mov lr, r0\n"                  \
        "pop {r0}\n"                    \
        "bx  lr\n"                      \
        :                               \
        : "i" (&HOTPATCH_ADDRESS(name)) \
        : "r0", "lr"                    \
    );                                  \
} while(0)

#define ORIGINAL_CODE()                   \
do {                                      \
    __asm__ volatile(                     \
        "hotpatch_original_code_"  STRINGIZE_COUNTER(__COUNTER__) ":\n" \
        ".word 0\n"                       \
        ".word 0\n"                       \
    );                                    \
} while(0)

#define CALL_FUNC_DEF(f)    \
do {                        \
    __asm__ volatile(\
        HOTPATCH_XSTRINGIFY(HOTPATCH_CONCAT(hotpatch_external_function_call_, f)) ":\n" \
        "ldr pc, [pc]\n" \
        ".word %c0\n" \
        : \
        : "i" (&(f)) \
        : \
    );\
} while(0)                           \



#define CALL_FUNC_UNK_DEF(f)    \
do {                        \
    extern void f(); \
    __asm__ volatile(\
        HOTPATCH_XSTRINGIFY(HOTPATCH_CONCAT(hotpatch_external_function_call_, f)) ":\n" \
        "ldr pc, [pc]\n" \
        ".word %c0\n" \
        : \
        : "i" (&(f)) \
        : \
    );\
} while(0)                           \

