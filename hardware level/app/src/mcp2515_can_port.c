#include "mcp2515_can_port.h"

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

    if (port_context == NULL || port_context->driver == NULL) {
        return false;
    }

    return mcp2515_try_receive_frame(port_context->driver, frame_out) == MCP2515_STATUS_OK;
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
