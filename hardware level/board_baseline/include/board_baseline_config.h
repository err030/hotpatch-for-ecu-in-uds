#ifndef BOARD_BASELINE_CONFIG_H
#define BOARD_BASELINE_CONFIG_H

#include "boards.h"
#include "nrfx_spim.h"
#include "uds_gateway.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Current MCP2515 wiring:
 *   P1.15 -> CLK/SCK
 *   P1.13 -> MOSI/SI
 *   P1.14 -> MISO/SO
 *   P1.12 -> CS
 *   P1.11 -> INT (reserved for interrupt-driven RX later)
 */
#define BOARD_MCP2515_SPI_INSTANCE_INDEX 3
#define BOARD_MCP2515_SPI_SCK_PIN        NRF_GPIO_PIN_MAP(1, 15)
#define BOARD_MCP2515_SPI_MOSI_PIN       NRF_GPIO_PIN_MAP(1, 13)
#define BOARD_MCP2515_SPI_MISO_PIN       NRF_GPIO_PIN_MAP(1, 14)
#define BOARD_MCP2515_SPI_CS_PIN         NRF_GPIO_PIN_MAP(1, 12)
#define BOARD_MCP2515_SPI_INT_PIN        NRF_GPIO_PIN_MAP(1, 11)
#define BOARD_MCP2515_SPI_FREQUENCY      NRF_SPIM_FREQ_1M

/*
 * Default timing is 1 Mb/s, matching the current CANable test setup.
 *
 * Check the metal crystal can on the MCP2515 module. It is usually marked
 * "8.000" or "16.000". The active profile below assumes a 16 MHz module.
 * If the module is 8 MHz, use the 8 MHz profile values instead.
 */
#define BOARD_MCP2515_OSCILLATOR_HZ 16000000UL
#define BOARD_CAN_BITRATE_BPS       1000000UL
#define BOARD_MCP2515_CNF1          0x00U
#define BOARD_MCP2515_CNF2          0x90U
#define BOARD_MCP2515_CNF3          0x02U

/* Alternative 8 MHz / 1 Mb/s profile, if the module crystal is marked 8.000:
 *   CNF1 = 0x00, CNF2 = 0x80, CNF3 = 0x00
 */

#define BOARD_UDS_EXTERNAL_REQUEST_CAN_ID  0x7E0U
#define BOARD_UDS_EXTERNAL_RESPONSE_CAN_ID 0x7E8U
#define BOARD_UDS_INTERNAL_REQUEST_CAN_ID  0x7E1U
#define BOARD_UDS_INTERNAL_RESPONSE_CAN_ID 0x7E9U
#define BOARD_UDS_GATEWAY_MODE             UDS_GATEWAY_MODE_MISCONFIGURED

#ifdef __cplusplus
}
#endif

#endif
