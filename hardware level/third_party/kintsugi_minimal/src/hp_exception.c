#include "hp_exception.h"

// Exposed diagnostic variables so host can verify MemManage events
// Place them in a dedicated section so their addresses are easy to find in the map/ELF
// Initialize with distinct markers so we can locate these words in RAM/flash
volatile uint32_t kintsugi_memmanage_count __attribute__((section(".data.kintsugi_diag"))) = 0x13579BDF;
volatile uint32_t kintsugi_last_mmfaddr __attribute__((section(".data.kintsugi_diag"))) = 0x2468ACE0;
volatile uint32_t kintsugi_attack_cyccnt __attribute__((section(".data.kintsugi_diag"))) = 0x0;
volatile uint32_t kintsugi_fault_cyccnt __attribute__((section(".data.kintsugi_diag"))) = 0x0;

#define KINTSUGI_TIMER NRF_TIMER2

static inline uint32_t kintsugi_read_cyccnt(void)
{
    KINTSUGI_TIMER->TASKS_CAPTURE[0] = 1;
    return KINTSUGI_TIMER->CC[0];
}

void hp_memmanage_handler(uint32_t *stack_frame) {
    int fault = SCB->ICSR & SCB_ICSR_VECTACTIVE_Msk;
    int hardfault = 0;
    uint32_t mmfar;

    if ((SCB->CFSR & SCB_CFSR_DACCVIOL_Msk) != 0) {
        if ((SCB->CFSR & SCB_CFSR_MMARVALID_Msk) != 0) {
            mmfar = SCB->MMFAR;

            // check if MMFAR is in the address range
            if ((mmfar >= HP_SLOT_START && mmfar < HP_SLOT_END)
                || (mmfar >= HP_CODE_START && mmfar < HP_CODE_END)
                || (mmfar >= HP_CONTEXT_START && mmfar < HP_CONTEXT_END)
                || (mmfar >= HP_QUARANTINE_START && mmfar < HP_QUARANTINE_END)) {
                    // The stacked PC is at offset 6 in exception stack frame
                    uint32_t pc = stack_frame[6];
                    uint16_t instr = *(uint16_t *)pc;

                    // Detect instruction length and skip it
                    if ((instr & 0xF800) >= 0xE800) {
                        stack_frame[6] += 4;
                    } else {
                        stack_frame[6] += 2;
                    }


                    /* Record the event in RAM (volatile) so the host can
                     * inspect these values with the debug probe if serial
                     * output is unavailable. */
                    kintsugi_memmanage_count++;
                    kintsugi_last_mmfaddr = mmfar;
                    kintsugi_fault_cyccnt = kintsugi_read_cyccnt();

                    #if defined(HP_SECURITY_EVALUATION) && !defined(HP_DISABLE_IMPORTANT_LOG)
                    DEBUG_LOG("[IMPORTANT]: Kintsugi prevented write at address 0x%08X\r\n", mmfar);
                    #endif

                    // Reset the memfault flag
                    SCB->CFSR |= SCB_CFSR_MEMFAULTSR_Msk;
            }
        }
    }
}

__attribute__((naked)) void MemoryManagement_Handler(void) {
    __asm volatile (
        "TST lr, #4        \n" 
        "ITE EQ            \n"
        "MRSEQ r0, MSP     \n"
        "MRSNE r0, PSP     \n"
        "B hp_memmanage_handler \n"
    );
}
