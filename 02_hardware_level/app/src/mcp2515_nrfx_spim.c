#include "mcp2515_nrfx_spim.h"

#ifdef BOARD_USE_NRFX_SPIM

#include <string.h>

#include "nrf_gpio.h"

void mcp2515_nrfx_spim_bus_init(
    mcp2515_spi_bus_t *spi_bus,
    mcp2515_nrfx_spim_context_t *context,
    nrfx_spim_t const *instance,
    uint32_t cs_pin
)
{
    if (spi_bus == NULL || context == NULL) {
        return;
    }

    context->instance = instance;
    context->cs_pin = cs_pin;
    spi_bus->exchange = mcp2515_nrfx_spim_exchange;
    spi_bus->context = context;
}

bool mcp2515_nrfx_spim_exchange(
    const uint8_t *tx_data,
    uint8_t *rx_data,
    size_t length,
    void *context
)
{
    mcp2515_nrfx_spim_context_t *spim_context =
        (mcp2515_nrfx_spim_context_t *)context;
    nrfx_spim_xfer_desc_t transfer;
    uint8_t discard_rx[32];
    nrfx_err_t err;

    if (spim_context == NULL || spim_context->instance == NULL ||
        tx_data == NULL || length == 0U) {
        return false;
    }

    memset(&transfer, 0, sizeof(transfer));
    transfer.p_tx_buffer = tx_data;
    transfer.tx_length = length;
    transfer.p_rx_buffer = rx_data != NULL ? rx_data : discard_rx;
    transfer.rx_length = length;

    nrf_gpio_pin_clear(spim_context->cs_pin);
    err = nrfx_spim_xfer(
        spim_context->instance,
        &transfer,
        0U
    );
    nrf_gpio_pin_set(spim_context->cs_pin);

    return err == NRFX_SUCCESS;
}

#endif
