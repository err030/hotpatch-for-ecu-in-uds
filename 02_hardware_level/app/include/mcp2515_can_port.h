#ifndef MCP2515_CAN_PORT_H
#define MCP2515_CAN_PORT_H

#include "board_adapter.h"
#include "mcp2515_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    mcp2515_driver_t *driver;
} mcp2515_can_port_context_t;

void mcp2515_can_port_init(
    uds_board_can_port_t *port,
    mcp2515_can_port_context_t *context,
    mcp2515_driver_t *driver
);

bool mcp2515_can_port_receive_frame(
    uds_can_frame_t *frame_out,
    void *context
);

bool mcp2515_can_port_send_frame(
    const uds_can_frame_t *frame,
    void *context
);

#ifdef __cplusplus
}
#endif

#endif
