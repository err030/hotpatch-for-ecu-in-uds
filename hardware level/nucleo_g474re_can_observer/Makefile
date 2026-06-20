PROJECT := nucleo_g474re_can_observer
BUILD_DIR := build

STM32CUBE_G4 ?= $(HOME)/stm32-tools/STM32Cube/Repository/STM32Cube_FW_G4_V1.6.3

CC := arm-none-eabi-gcc
AS := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy
SIZE := arm-none-eabi-size

CPU_FLAGS := -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard
DEFS := -DSTM32G474xx -DUSE_HAL_DRIVER
FDCAN_PINS ?= PB8_PB9
FDCAN_MODE ?= BUS_MONITORING
CAN_LED_TEST ?= 0
LED_SELF_TEST ?= 0

ifeq ($(FDCAN_PINS),PB8_PB9)
DEFS += -DNUCLEO_OBSERVER_FDCAN_PINS_PB8_PB9
else ifneq ($(FDCAN_PINS),PA11_PA12)
$(error Unsupported FDCAN_PINS=$(FDCAN_PINS). Use PB8_PB9 or PA11_PA12)
endif

ifeq ($(FDCAN_MODE),NORMAL)
DEFS += -DNUCLEO_OBSERVER_FDCAN_MODE_NORMAL
else ifneq ($(FDCAN_MODE),BUS_MONITORING)
$(error Unsupported FDCAN_MODE=$(FDCAN_MODE). Use BUS_MONITORING or NORMAL)
endif

ifeq ($(CAN_LED_TEST),1)
DEFS += -DNUCLEO_OBSERVER_CAN_LED_TEST
endif

ifeq ($(LED_SELF_TEST),1)
DEFS += -DNUCLEO_OBSERVER_LED_SELF_TEST
endif

INCLUDES := \
  -ICore/Inc \
  -I$(STM32CUBE_G4)/Drivers/STM32G4xx_HAL_Driver/Inc \
  -I$(STM32CUBE_G4)/Drivers/STM32G4xx_HAL_Driver/Inc/Legacy \
  -I$(STM32CUBE_G4)/Drivers/CMSIS/Device/ST/STM32G4xx/Include \
  -I$(STM32CUBE_G4)/Drivers/CMSIS/Include

CFLAGS := $(CPU_FLAGS) $(DEFS) $(INCLUDES) -Og -g3 -Wall -Wextra -ffunction-sections -fdata-sections
ASFLAGS := $(CPU_FLAGS) $(DEFS) $(INCLUDES) -x assembler-with-cpp -g3
LDFLAGS := $(CPU_FLAGS) -TSTM32G474RETX_FLASH.ld -Wl,-Map=$(BUILD_DIR)/$(PROJECT).map,--cref -Wl,--gc-sections --specs=nano.specs --specs=nosys.specs

HAL_SRC := $(STM32CUBE_G4)/Drivers/STM32G4xx_HAL_Driver/Src
CMSIS_DEV_SRC := $(STM32CUBE_G4)/Drivers/CMSIS/Device/ST/STM32G4xx/Source/Templates

C_SOURCES := \
  Core/Src/main.c \
  Core/Src/stm32g4xx_hal_msp.c \
  Core/Src/stm32g4xx_it.c \
  Core/Src/can_observer_user.c \
  $(CMSIS_DEV_SRC)/system_stm32g4xx.c \
  $(HAL_SRC)/stm32g4xx_hal.c \
  $(HAL_SRC)/stm32g4xx_hal_cortex.c \
  $(HAL_SRC)/stm32g4xx_hal_dma.c \
  $(HAL_SRC)/stm32g4xx_hal_dma_ex.c \
  $(HAL_SRC)/stm32g4xx_hal_fdcan.c \
  $(HAL_SRC)/stm32g4xx_hal_flash.c \
  $(HAL_SRC)/stm32g4xx_hal_flash_ex.c \
  $(HAL_SRC)/stm32g4xx_hal_gpio.c \
  $(HAL_SRC)/stm32g4xx_hal_pwr.c \
  $(HAL_SRC)/stm32g4xx_hal_pwr_ex.c \
  $(HAL_SRC)/stm32g4xx_hal_rcc.c \
  $(HAL_SRC)/stm32g4xx_hal_rcc_ex.c \
  $(HAL_SRC)/stm32g4xx_hal_uart.c \
  $(HAL_SRC)/stm32g4xx_hal_uart_ex.c

ASM_SOURCES := $(STM32CUBE_G4)/Drivers/CMSIS/Device/ST/STM32G4xx/Source/Templates/gcc/startup_stm32g474xx.s

OBJECTS := $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.s=.o)))

vpath %.c $(sort $(dir $(C_SOURCES)))
vpath %.s $(sort $(dir $(ASM_SOURCES)))

.PHONY: all clean flash drag-flash size

all: $(BUILD_DIR)/$(PROJECT).elf $(BUILD_DIR)/$(PROJECT).bin

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/%.o: %.s Makefile | $(BUILD_DIR)
	$(AS) $(ASFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/$(PROJECT).elf: $(OBJECTS) STM32G474RETX_FLASH.ld
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	$(SIZE) $@

$(BUILD_DIR)/$(PROJECT).bin: $(BUILD_DIR)/$(PROJECT).elf
	$(OBJCOPY) -O binary $< $@

size: $(BUILD_DIR)/$(PROJECT).elf
	$(SIZE) $<

flash: $(BUILD_DIR)/$(PROJECT).bin
	STM32_Programmer_CLI -c port=SWD -w $< 0x08000000 -v -rst

drag-flash: $(BUILD_DIR)/$(PROJECT).bin
	cp $< /media/beibei/NOD_G474RE/
	sync

clean:
	rm -rf $(BUILD_DIR)

-include $(OBJECTS:.o=.d)
