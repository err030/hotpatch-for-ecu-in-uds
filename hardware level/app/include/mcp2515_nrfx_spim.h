#ifndef MCP2515_NRFX_SPIM_H
#define MCP2515_NRFX_SPIM_H

#include "mcp2515_driver.h"

#ifdef BOARD_USE_NRFX_SPIM

#include <stdint.h>

#include "nrfx_spim.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    nrfx_spim_t const *instance;
    uint32_t cs_pin;
} mcp2515_nrfx_spim_context_t;

void mcp2515_nrfx_spim_bus_init(
    mcp2515_spi_bus_t *spi_bus,
    mcp2515_nrfx_spim_context_t *context,
    nrfx_spim_t const *instance,
    uint32_t cs_pin
);

bool mcp2515_nrfx_spim_exchange(
    const uint8_t *tx_data,
    uint8_t *rx_data,
    size_t length,
    void *context
);

#ifdef __cplusplus
}
#endif

#endif

#endif
