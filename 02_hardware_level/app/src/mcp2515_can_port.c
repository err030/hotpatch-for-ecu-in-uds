#include "mcp2515_can_port.h"

#define MCP2515_REG_TEC 0x1CU
#define MCP2515_REG_REC 0x1DU
#define MCP2515_REG_CANINTF 0x2CU
#define MCP2515_REG_EFLG 0x2DU

volatile uint32_t g_mcp2515_port_poll_count = 0x00000000UL;
volatile uint32_t g_mcp2515_port_rx_ok_count = 0x00000000UL;
volatile uint32_t g_mcp2515_port_no_frame_count = 0x00000000UL;
volatile uint32_t g_mcp2515_port_error_count = 0x00000000UL;
volatile uint32_t g_mcp2515_port_last_status = 0xFFFFFFFFUL;
volatile uint32_t g_mcp2515_port_last_canintf = 0xFFFFFFFFUL;
volatile uint32_t g_mcp2515_port_last_eflg = 0xFFFFFFFFUL;
volatile uint32_t g_mcp2515_port_last_tec = 0xFFFFFFFFUL;
volatile uint32_t g_mcp2515_port_last_rec = 0xFFFFFFFFUL;

static void mcp2515_can_port_capture_status(mcp2515_driver_t *driver)
{
    uint8_t value;

    if (driver == NULL) {
        return;
    }

    if (mcp2515_read_register(driver, MCP2515_REG_CANINTF, &value) == MCP2515_STATUS_OK) {
        g_mcp2515_port_last_canintf = value;
    }
    if (mcp2515_read_register(driver, MCP2515_REG_EFLG, &value) == MCP2515_STATUS_OK) {
        g_mcp2515_port_last_eflg = value;
    }
    if (mcp2515_read_register(driver, MCP2515_REG_TEC, &value) == MCP2515_STATUS_OK) {
        g_mcp2515_port_last_tec = value;
    }
    if (mcp2515_read_register(driver, MCP2515_REG_REC, &value) == MCP2515_STATUS_OK) {
        g_mcp2515_port_last_rec = value;
    }
}

void mcp2515_can_port_init(
    uds_board_can_port_t *port,
    mcp2515_can_port_context_t *context,
    mcp2515_driver_t *driver
)
{
    if (port == NULL || context == NULL) {
        return;
    }

    context->driver = driver;
    port->receive_frame = mcp2515_can_port_receive_frame;
    port->send_frame = mcp2515_can_port_send_frame;
    port->context = context;
}

bool mcp2515_can_port_receive_frame(
    uds_can_frame_t *frame_out,
    void *context
)
{
    mcp2515_can_port_context_t *port_context =
        (mcp2515_can_port_context_t *)context;
    mcp2515_status_t status;

    if (port_context == NULL || port_context->driver == NULL) {
        return false;
    }

    g_mcp2515_port_poll_count++;
    status = mcp2515_try_receive_frame(port_context->driver, frame_out);
    g_mcp2515_port_last_status = (uint32_t)status;
    mcp2515_can_port_capture_status(port_context->driver);

    if (status == MCP2515_STATUS_OK) {
        g_mcp2515_port_rx_ok_count++;
        return true;
    }
    if (status == MCP2515_STATUS_NO_FRAME) {
        g_mcp2515_port_no_frame_count++;
    } else {
        g_mcp2515_port_error_count++;
    }

    return false;
}

bool mcp2515_can_port_send_frame(
    const uds_can_frame_t *frame,
    void *context
)
{
    mcp2515_can_port_context_t *port_context =
        (mcp2515_can_port_context_t *)context;

    if (port_context == NULL || port_context->driver == NULL) {
        return false;
    }

    return mcp2515_send_frame(port_context->driver, frame) == MCP2515_STATUS_OK;
}
