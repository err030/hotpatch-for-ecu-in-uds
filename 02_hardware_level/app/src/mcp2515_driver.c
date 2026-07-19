#include "mcp2515_driver.h"

#include <string.h>

#define MCP2515_CMD_RESET 0xC0U
#define MCP2515_CMD_READ 0x03U
#define MCP2515_CMD_WRITE 0x02U
#define MCP2515_CMD_BIT_MODIFY 0x05U
#define MCP2515_CMD_READ_STATUS 0xA0U

#define MCP2515_REG_CANSTAT 0x0EU
#define MCP2515_REG_CANCTRL 0x0FU
#define MCP2515_REG_CNF3 0x28U
#define MCP2515_REG_CNF2 0x29U
#define MCP2515_REG_CNF1 0x2AU
#define MCP2515_REG_CANINTE 0x2BU
#define MCP2515_REG_CANINTF 0x2CU
#define MCP2515_REG_TXB0SIDH 0x31U
#define MCP2515_REG_RXB0CTRL 0x60U
#define MCP2515_REG_RXB0SIDH 0x61U

#define MCP2515_CANINTF_RX0IF 0x01U
#define MCP2515_CANCTRL_REQOP_MASK 0xE0U
#define MCP2515_CANCTRL_MODE_NORMAL 0x00U
#define MCP2515_CANCTRL_MODE_LOOPBACK 0x40U
#define MCP2515_CANCTRL_MODE_CONFIG 0x80U

#define MCP2515_RESET_SETTLE_LOOPS 640000U
#define MCP2515_MODE_POLL_ATTEMPTS 32U
#define MCP2515_MODE_POLL_DELAY_LOOPS 64000U

static void mcp2515_delay_loops(uint32_t loops)
{
    volatile uint32_t remaining = loops;

    while (remaining > 0U) {
        remaining--;
    }
}

static mcp2515_status_t mcp2515_exchange(
    mcp2515_driver_t *driver,
    const uint8_t *tx_data,
    uint8_t *rx_data,
    size_t length
)
{
    if (driver == NULL || driver->spi_bus.exchange == NULL || tx_data == NULL || length == 0U) {
        return MCP2515_STATUS_INVALID_ARG;
    }

    if (!driver->spi_bus.exchange(tx_data, rx_data, length, driver->spi_bus.context)) {
        return MCP2515_STATUS_IO_ERROR;
    }

    return MCP2515_STATUS_OK;
}

static void mcp2515_encode_standard_id(
    uint16_t standard_id,
    uint8_t *sidh_out,
    uint8_t *sidl_out
)
{
    *sidh_out = (uint8_t)(standard_id >> 3);
    *sidl_out = (uint8_t)((standard_id & 0x0007U) << 5);
}

static uint16_t mcp2515_decode_standard_id(
    uint8_t sidh,
    uint8_t sidl
)
{
    return (uint16_t)(((uint16_t)sidh << 3) | (uint16_t)(sidl >> 5));
}

static mcp2515_status_t mcp2515_set_mode(
    mcp2515_driver_t *driver,
    uint8_t requested_mode
)
{
    uint8_t canstat = 0U;
    mcp2515_status_t status;
    uint32_t attempt;

    status = mcp2515_bit_modify(
        driver,
        MCP2515_REG_CANCTRL,
        MCP2515_CANCTRL_REQOP_MASK,
        requested_mode
    );
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    for (attempt = 0U; attempt < MCP2515_MODE_POLL_ATTEMPTS; attempt++) {
        status = mcp2515_read_register(driver, MCP2515_REG_CANSTAT, &canstat);
        if (status != MCP2515_STATUS_OK) {
            return status;
        }

        if ((canstat & MCP2515_CANCTRL_REQOP_MASK) == requested_mode) {
            return MCP2515_STATUS_OK;
        }

        mcp2515_delay_loops(MCP2515_MODE_POLL_DELAY_LOOPS);
    }

    return MCP2515_STATUS_MODE_MISMATCH;
}

void mcp2515_driver_init(
    mcp2515_driver_t *driver,
    const mcp2515_spi_bus_t *spi_bus
)
{
    if (driver == NULL) {
        return;
    }

    memset(driver, 0, sizeof(*driver));
    if (spi_bus != NULL) {
        driver->spi_bus = *spi_bus;
    }
}

mcp2515_status_t mcp2515_reset(mcp2515_driver_t *driver)
{
    const uint8_t tx_data[1] = {MCP2515_CMD_RESET};
    mcp2515_status_t status = mcp2515_exchange(driver, tx_data, NULL, sizeof(tx_data));

    if (status == MCP2515_STATUS_OK) {
        mcp2515_delay_loops(MCP2515_RESET_SETTLE_LOOPS);
    }

    return status;
}

mcp2515_status_t mcp2515_read_register(
    mcp2515_driver_t *driver,
    uint8_t address,
    uint8_t *value_out
)
{
    uint8_t tx_data[3] = {MCP2515_CMD_READ, address, 0x00U};
    uint8_t rx_data[3] = {0U};
    mcp2515_status_t status;

    if (value_out == NULL) {
        return MCP2515_STATUS_INVALID_ARG;
    }

    status = mcp2515_exchange(driver, tx_data, rx_data, sizeof(tx_data));
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    *value_out = rx_data[2];
    return MCP2515_STATUS_OK;
}

mcp2515_status_t mcp2515_write_register(
    mcp2515_driver_t *driver,
    uint8_t address,
    uint8_t value
)
{
    const uint8_t tx_data[3] = {MCP2515_CMD_WRITE, address, value};
    return mcp2515_exchange(driver, tx_data, NULL, sizeof(tx_data));
}

mcp2515_status_t mcp2515_bit_modify(
    mcp2515_driver_t *driver,
    uint8_t address,
    uint8_t mask,
    uint8_t value
)
{
    const uint8_t tx_data[4] = {MCP2515_CMD_BIT_MODIFY, address, mask, value};
    return mcp2515_exchange(driver, tx_data, NULL, sizeof(tx_data));
}

mcp2515_status_t mcp2515_read_status(
    mcp2515_driver_t *driver,
    uint8_t *status_out
)
{
    uint8_t tx_data[2] = {MCP2515_CMD_READ_STATUS, 0x00U};
    uint8_t rx_data[2] = {0U};
    mcp2515_status_t status;

    if (status_out == NULL) {
        return MCP2515_STATUS_INVALID_ARG;
    }

    status = mcp2515_exchange(driver, tx_data, rx_data, sizeof(tx_data));
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    *status_out = rx_data[1];
    return MCP2515_STATUS_OK;
}

mcp2515_status_t mcp2515_capture_diagnostics(
    mcp2515_driver_t *driver,
    mcp2515_diagnostics_t *diagnostics_out
)
{
    if (diagnostics_out == NULL) {
        return MCP2515_STATUS_INVALID_ARG;
    }

    memset(diagnostics_out, 0, sizeof(*diagnostics_out));
    diagnostics_out->read_canstat_status = mcp2515_read_register(
        driver,
        MCP2515_REG_CANSTAT,
        &diagnostics_out->canstat
    );
    diagnostics_out->read_canctrl_status = mcp2515_read_register(
        driver,
        MCP2515_REG_CANCTRL,
        &diagnostics_out->canctrl
    );
    diagnostics_out->read_status_status = mcp2515_read_status(
        driver,
        &diagnostics_out->read_status
    );

    if (diagnostics_out->read_canstat_status != MCP2515_STATUS_OK) {
        return diagnostics_out->read_canstat_status;
    }
    if (diagnostics_out->read_canctrl_status != MCP2515_STATUS_OK) {
        return diagnostics_out->read_canctrl_status;
    }
    return diagnostics_out->read_status_status;
}

mcp2515_status_t mcp2515_load_bitrate_registers(
    mcp2515_driver_t *driver,
    uint8_t cnf1,
    uint8_t cnf2,
    uint8_t cnf3
)
{
    mcp2515_status_t status;

    status = mcp2515_write_register(driver, MCP2515_REG_CNF1, cnf1);
    if (status != MCP2515_STATUS_OK) {
        return status;
    }
    status = mcp2515_write_register(driver, MCP2515_REG_CNF2, cnf2);
    if (status != MCP2515_STATUS_OK) {
        return status;
    }
    return mcp2515_write_register(driver, MCP2515_REG_CNF3, cnf3);
}

mcp2515_status_t mcp2515_set_normal_mode(mcp2515_driver_t *driver)
{
    return mcp2515_set_mode(driver, MCP2515_CANCTRL_MODE_NORMAL);
}

mcp2515_status_t mcp2515_set_loopback_mode(mcp2515_driver_t *driver)
{
    return mcp2515_set_mode(driver, MCP2515_CANCTRL_MODE_LOOPBACK);
}

mcp2515_status_t mcp2515_initialize_basic(
    mcp2515_driver_t *driver,
    uint8_t cnf1,
    uint8_t cnf2,
    uint8_t cnf3,
    bool loopback_mode
)
{
    mcp2515_status_t status;

    status = mcp2515_reset(driver);
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    status = mcp2515_set_mode(driver, MCP2515_CANCTRL_MODE_CONFIG);
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    status = mcp2515_load_bitrate_registers(driver, cnf1, cnf2, cnf3);
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    status = mcp2515_write_register(driver, MCP2515_REG_RXB0CTRL, 0x60U);
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    status = mcp2515_write_register(driver, MCP2515_REG_CANINTE, MCP2515_CANINTF_RX0IF);
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    status = mcp2515_write_register(driver, MCP2515_REG_CANINTF, 0x00U);
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    if (loopback_mode) {
        return mcp2515_set_loopback_mode(driver);
    }

    return mcp2515_set_normal_mode(driver);
}

mcp2515_status_t mcp2515_try_receive_frame(
    mcp2515_driver_t *driver,
    uds_can_frame_t *frame_out
)
{
    uint8_t intf = 0U;
    uint8_t tx_data[15] = {0U};
    uint8_t rx_data[15] = {0U};
    uint8_t dlc;
    mcp2515_status_t status;

    if (frame_out == NULL) {
        return MCP2515_STATUS_INVALID_ARG;
    }

    status = mcp2515_read_register(driver, MCP2515_REG_CANINTF, &intf);
    if (status != MCP2515_STATUS_OK) {
        return status;
    }
    if ((intf & MCP2515_CANINTF_RX0IF) == 0U) {
        return MCP2515_STATUS_NO_FRAME;
    }

    tx_data[0] = MCP2515_CMD_READ;
    tx_data[1] = MCP2515_REG_RXB0SIDH;
    status = mcp2515_exchange(driver, tx_data, rx_data, sizeof(tx_data));
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    dlc = (uint8_t)(rx_data[6] & 0x0FU);
    if (dlc > UDS_CAN_MAX_DATA_LENGTH) {
        return MCP2515_STATUS_UNSUPPORTED_FRAME;
    }

    memset(frame_out, 0, sizeof(*frame_out));
    frame_out->arbitration_id = mcp2515_decode_standard_id(rx_data[2], rx_data[3]);
    frame_out->dlc = dlc;
    if (dlc > 0U) {
        memcpy(frame_out->data, &rx_data[7], dlc);
    }

    return mcp2515_bit_modify(driver, MCP2515_REG_CANINTF, MCP2515_CANINTF_RX0IF, 0x00U);
}

mcp2515_status_t mcp2515_send_frame(
    mcp2515_driver_t *driver,
    const uds_can_frame_t *frame
)
{
    uint8_t tx_data[15] = {0U};
    uint8_t sidh;
    uint8_t sidl;
    mcp2515_status_t status;

    if (frame == NULL) {
        return MCP2515_STATUS_INVALID_ARG;
    }
    if (frame->arbitration_id > MCP2515_STANDARD_ID_MAX ||
        frame->dlc > UDS_CAN_MAX_DATA_LENGTH) {
        return MCP2515_STATUS_UNSUPPORTED_FRAME;
    }

    mcp2515_encode_standard_id((uint16_t)frame->arbitration_id, &sidh, &sidl);
    tx_data[0] = MCP2515_CMD_WRITE;
    tx_data[1] = MCP2515_REG_TXB0SIDH;
    tx_data[2] = sidh;
    tx_data[3] = sidl;
    tx_data[4] = 0x00U;
    tx_data[5] = 0x00U;
    tx_data[6] = (uint8_t)(frame->dlc & 0x0FU);
    if (frame->dlc > 0U) {
        memcpy(&tx_data[7], frame->data, frame->dlc);
    }

    status = mcp2515_exchange(driver, tx_data, NULL, sizeof(tx_data));
    if (status != MCP2515_STATUS_OK) {
        return status;
    }

    {
        const uint8_t rts_command[1] = {0x81U};
        return mcp2515_exchange(driver, rts_command, NULL, sizeof(rts_command));
    }
}
