
#include "hp_helper.h"
#include <zephyr/drivers/gpio.h>
#include <zephyr/internal/syscall_handler.h>

#pragma GCC push_options
#pragma GCC optimize ("O0")
HOTPATCH_FUNCTION_START_NAKED(z_mrsh_gpio_pin_configure, 0x6, redirect, 8) {
	VAR_REG(port, "r0", const struct device *);
   
	if (((struct gpio_driver_api *)(port->api))->pin_configure == 0x0) {
		SET_RETURN_VALUE(0);
		RESTORE_REGISTERS("r3 - r7, pc");
	}
	HOTPATCH_BRANCH_TO_ORIGINAL_CODE();
}
#pragma GCC pop_options