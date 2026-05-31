#ifndef MCP2515_DRIVER_H
#define MCP2515_DRIVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "uds_link.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MCP2515_STANDARD_ID_MAX 0x7FFU

typedef enum {
    MCP2515_STATUS_OK = 0,
    MCP2515_STATUS_INVALID_ARG,
    MCP2515_STATUS_IO_ERROR,
    MCP2515_STATUS_NO_FRAME,
    MCP2515_STATUS_UNSUPPORTED_FRAME,
    MCP2515_STATUS_MODE_MISMATCH,
} mcp2515_status_t;

typedef bool (*mcp2515_spi_exchange_fn)(
    const uint8_t *tx_data,
    uint8_t *rx_data,
    size_t length,
    void *context
);

typedef struct {
    mcp2515_spi_exchange_fn exchange;
    void *context;
} mcp2515_spi_bus_t;

typedef struct {
    mcp2515_spi_bus_t spi_bus;
} mcp2515_driver_t;

typedef struct {
    mcp2515_status_t read_canstat_status;
    mcp2515_status_t read_canctrl_status;
    mcp2515_status_t read_status_status;
    uint8_t canstat;
    uint8_t canctrl;
    uint8_t read_status;
} mcp2515_diagnostics_t;

void mcp2515_driver_init(
    mcp2515_driver_t *driver,
    const mcp2515_spi_bus_t *spi_bus
);

mcp2515_status_t mcp2515_reset(mcp2515_driver_t *driver);
mcp2515_status_t mcp2515_read_register(
    mcp2515_driver_t *driver,
    uint8_t address,
    uint8_t *value_out
);
mcp2515_status_t mcp2515_write_register(
    mcp2515_driver_t *driver,
    uint8_t address,
    uint8_t value
);
mcp2515_status_t mcp2515_bit_modify(
    mcp2515_driver_t *driver,
    uint8_t address,
    uint8_t mask,
    uint8_t value
);
mcp2515_status_t mcp2515_read_status(
    mcp2515_driver_t *driver,
    uint8_t *status_out
);
mcp2515_status_t mcp2515_capture_diagnostics(
    mcp2515_driver_t *driver,
    mcp2515_diagnostics_t *diagnostics_out
);
mcp2515_status_t mcp2515_load_bitrate_registers(
    mcp2515_driver_t *driver,
    uint8_t cnf1,
    uint8_t cnf2,
    uint8_t cnf3
);
mcp2515_status_t mcp2515_set_normal_mode(mcp2515_driver_t *driver);
mcp2515_status_t mcp2515_set_loopback_mode(mcp2515_driver_t *driver);
mcp2515_status_t mcp2515_initialize_basic(
    mcp2515_driver_t *driver,
    uint8_t cnf1,
    uint8_t cnf2,
    uint8_t cnf3,
    bool loopback_mode
);
mcp2515_status_t mcp2515_try_receive_frame(
    mcp2515_driver_t *driver,
    uds_can_frame_t *frame_out
);
mcp2515_status_t mcp2515_send_frame(
    mcp2515_driver_t *driver,
    const uds_can_frame_t *frame
);

#ifdef __cplusplus
}
#endif

#endif
