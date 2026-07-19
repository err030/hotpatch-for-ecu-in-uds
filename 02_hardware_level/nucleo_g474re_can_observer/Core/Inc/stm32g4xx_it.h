#ifndef STM32G4XX_IT_H
#define STM32G4XX_IT_H

#ifdef __cplusplus
extern "C" {
#endif

void NMI_Handler(void);
void HardFault_Handler(void);
void SVC_Handler(void);
void PendSV_Handler(void);
void SysTick_Handler(void);
void FDCAN1_IT0_IRQHandler(void);

#ifdef __cplusplus
}
#endif

#endif /* STM32G4XX_IT_H */
