#include <stdbool.h>
#include <stdint.h>

#include "FreeRTOS.h"
#include "app_error.h"
#include "board_baseline_config.h"
#include "board_kintsugi_bridge.h"
#include "board_log.h"
#include "board_runtime.h"
#include "board_task.h"
#include "mcp2515_can_port.h"
#include "mcp2515_driver.h"
#include "mcp2515_nrfx_spim.h"
#include "nrf_drv_clock.h"
#include "nrf_delay.h"
#include "nrf_gpio.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "nrfx_spim.h"
#include "task.h"
#include "uds_ecu.h"
#include "uds_gateway.h"
#include "uds_link.h"

#ifndef UDS_REQUEST_CAN_ID
#define UDS_REQUEST_CAN_ID BOARD_UDS_EXTERNAL_REQUEST_CAN_ID
#endif

#ifndef UDS_RESPONSE_CAN_ID
#define UDS_RESPONSE_CAN_ID BOARD_UDS_EXTERNAL_RESPONSE_CAN_ID
#endif

#ifndef MCP2515_SPI_INSTANCE_INDEX
#define MCP2515_SPI_INSTANCE_INDEX BOARD_MCP2515_SPI_INSTANCE_INDEX
#endif

#ifndef MCP2515_SPI_SCK_PIN
#define MCP2515_SPI_SCK_PIN BOARD_MCP2515_SPI_SCK_PIN
#endif

#ifndef MCP2515_SPI_MOSI_PIN
#define MCP2515_SPI_MOSI_PIN BOARD_MCP2515_SPI_MOSI_PIN
#endif

#ifndef MCP2515_SPI_MISO_PIN
#define MCP2515_SPI_MISO_PIN BOARD_MCP2515_SPI_MISO_PIN
#endif

#ifndef MCP2515_SPI_CS_PIN
#define MCP2515_SPI_CS_PIN BOARD_MCP2515_SPI_CS_PIN
#endif

#ifndef MCP2515_SPI_FREQUENCY
#define MCP2515_SPI_FREQUENCY BOARD_MCP2515_SPI_FREQUENCY
#endif

#ifndef MCP2515_CNF1
#define MCP2515_CNF1 BOARD_MCP2515_CNF1
#endif

#ifndef MCP2515_CNF2
#define MCP2515_CNF2 BOARD_MCP2515_CNF2
#endif

#ifndef MCP2515_CNF3
#define MCP2515_CNF3 BOARD_MCP2515_CNF3
#endif

#ifndef UDS_TASK_STACK_SIZE
#define UDS_TASK_STACK_SIZE 768U
#endif

#ifndef UDS_TASK_PRIORITY
#define UDS_TASK_PRIORITY 1U
#endif

#ifndef UDS_TASK_IDLE_DELAY_TICKS
#define UDS_TASK_IDLE_DELAY_TICKS 1U
#endif

static const nrfx_spim_t g_spim = NRFX_SPIM_INSTANCE(MCP2515_SPI_INSTANCE_INDEX);
static uds_gateway_route_t g_gateway_route;
static uds_gateway_t g_gateway;
static uds_gateway_task_t g_gateway_task;
static uds_ecu_t g_adjacent_ecu;
static uds_ecu_task_t g_adjacent_ecu_task;
static uds_board_adapter_t g_board_adapter;
static uds_board_runtime_t g_board_runtime;
static uds_board_task_context_t g_board_task_context;
#if (BOARD_UDS_KINTSUGI_BRIDGE_ENABLED == 1)
static board_kintsugi_bridge_t g_kintsugi_bridge;
#endif
static mcp2515_driver_t g_mcp2515_driver;
static mcp2515_nrfx_spim_context_t g_mcp2515_spim_context;
static mcp2515_can_port_context_t g_mcp2515_can_port_context;
static uds_board_can_port_t g_can_port;

volatile uint32_t g_board_mcp2515_init_status = 0xFFFFFFFFUL;
volatile uint32_t g_board_mcp2515_canstat = 0xFFFFFFFFUL;
volatile uint32_t g_board_mcp2515_canctrl = 0xFFFFFFFFUL;
volatile uint32_t g_board_mcp2515_read_status = 0xFFFFFFFFUL;
volatile uint32_t g_board_mcp2515_canstat_read_status = 0xFFFFFFFFUL;
volatile uint32_t g_board_mcp2515_canctrl_read_status = 0xFFFFFFFFUL;
volatile uint32_t g_board_mcp2515_status_read_status = 0xFFFFFFFFUL;
volatile uint32_t g_board_startup_test_tx_attempt_count = 0x00000000UL;
volatile uint32_t g_board_startup_test_tx_ok_count = 0x00000000UL;
volatile uint32_t g_board_startup_test_tx_last_status = 0xFFFFFFFFUL;
volatile uint32_t g_board_loopback_init_status = 0xFFFFFFFFUL;
volatile uint32_t g_board_loopback_tx_status = 0xFFFFFFFFUL;
volatile uint32_t g_board_loopback_rx_status = 0xFFFFFFFFUL;
volatile uint32_t g_board_loopback_rx_can_id = 0xFFFFFFFFUL;
volatile uint32_t g_board_loopback_rx_data_word0 = 0xFFFFFFFFUL;
volatile uint32_t g_board_loopback_rx_data_word1 = 0xFFFFFFFFUL;

static bool board_wiring_configured(void)
{
    return MCP2515_SPI_SCK_PIN != NRFX_SPIM_PIN_NOT_USED &&
           MCP2515_SPI_MOSI_PIN != NRFX_SPIM_PIN_NOT_USED &&
           MCP2515_SPI_MISO_PIN != NRFX_SPIM_PIN_NOT_USED &&
           MCP2515_SPI_CS_PIN != NRFX_SPIM_PIN_NOT_USED;
}

static bool board_mcp2515_timing_configured(void)
{
    return MCP2515_CNF1 != 0x00U || MCP2515_CNF2 != 0x00U || MCP2515_CNF3 != 0x00U;
}

static void board_runtime_delay_hook(
    uint32_t delay_ticks,
    void *context
)
{
    (void)context;
    vTaskDelay(delay_ticks);
}

static void board_clock_init(void)
{
    ret_code_t err_code;

    err_code = nrf_drv_clock_init();
    if (err_code != NRF_ERROR_MODULE_ALREADY_INITIALIZED) {
        APP_ERROR_CHECK(err_code);
    }
    nrf_drv_clock_lfclk_request(NULL);
}

static void board_logs_init(void)
{
    APP_ERROR_CHECK(NRF_LOG_INIT(NULL));
    NRF_LOG_DEFAULT_BACKENDS_INIT();
}

static void board_spim_init(void)
{
    nrfx_spim_config_t spim_config = NRFX_SPIM_DEFAULT_CONFIG;

#ifdef BSP_QSPI_CSN_PIN
    nrf_gpio_cfg_output(BSP_QSPI_CSN_PIN);
    nrf_gpio_pin_set(BSP_QSPI_CSN_PIN);
#endif

    spim_config.sck_pin = MCP2515_SPI_SCK_PIN;
    spim_config.mosi_pin = MCP2515_SPI_MOSI_PIN;
    spim_config.miso_pin = MCP2515_SPI_MISO_PIN;
    spim_config.ss_pin = NRFX_SPIM_PIN_NOT_USED;
    spim_config.frequency = MCP2515_SPI_FREQUENCY;
    spim_config.mode = NRF_SPIM_MODE_0;
    spim_config.bit_order = NRF_SPIM_BIT_ORDER_MSB_FIRST;

    nrf_gpio_cfg_output(MCP2515_SPI_CS_PIN);
    nrf_gpio_pin_set(MCP2515_SPI_CS_PIN);
    APP_ERROR_CHECK(nrfx_spim_init(&g_spim, &spim_config, NULL, NULL));
}

static void board_diag_runtime_init(void)
{
    mcp2515_spi_bus_t spi_bus;
    mcp2515_status_t mcp_status;
    mcp2515_diagnostics_t mcp_diagnostics;

    g_gateway_route.external_request_id = BOARD_UDS_EXTERNAL_REQUEST_CAN_ID;
    g_gateway_route.internal_request_id = BOARD_UDS_INTERNAL_REQUEST_CAN_ID;
    g_gateway_route.internal_response_id = BOARD_UDS_INTERNAL_RESPONSE_CAN_ID;
    g_gateway_route.external_response_id = BOARD_UDS_EXTERNAL_RESPONSE_CAN_ID;

    uds_gateway_init(
        &g_gateway,
        &g_gateway_route,
        BOARD_UDS_GATEWAY_MODE
    );
    uds_gateway_task_init(&g_gateway_task, &g_gateway);
#if (BOARD_UDS_ECU_PROFILE == BOARD_UDS_ECU_PROFILE_VULNERABLE)
    uds_ecu_init_vulnerable(
        &g_adjacent_ecu,
        BOARD_UDS_INTERNAL_REQUEST_CAN_ID,
        BOARD_UDS_INTERNAL_RESPONSE_CAN_ID
    );
#else
    uds_ecu_init_strict(
        &g_adjacent_ecu,
        BOARD_UDS_INTERNAL_REQUEST_CAN_ID,
        BOARD_UDS_INTERNAL_RESPONSE_CAN_ID
    );
#endif
#if (BOARD_UDS_APPLY_SECURITY_ACCESS_HOTPATCH == 1)
    uds_ecu_apply_security_access_hotpatch(&g_adjacent_ecu);
#endif
    uds_ecu_task_init(&g_adjacent_ecu_task, &g_adjacent_ecu);
    uds_board_adapter_init_gateway_path(
        &g_board_adapter,
        &g_gateway_task,
        &g_adjacent_ecu_task
    );
#if (BOARD_UDS_KINTSUGI_BRIDGE_ENABLED == 1)
    board_kintsugi_bridge_init(&g_kintsugi_bridge, &g_adjacent_ecu);
    uds_board_adapter_set_control_hook(
        &g_board_adapter,
        board_kintsugi_bridge_control_hook,
        &g_kintsugi_bridge
    );
#endif
    mcp2515_nrfx_spim_bus_init(
        &spi_bus,
        &g_mcp2515_spim_context,
        &g_spim,
        MCP2515_SPI_CS_PIN
    );
    mcp2515_driver_init(&g_mcp2515_driver, &spi_bus);

#if (BOARD_MCP2515_INTERNAL_LOOPBACK_SELF_TEST_ENABLED == 1)
    {
        uds_can_frame_t tx_frame;
        uds_can_frame_t rx_frame;

        g_board_loopback_init_status = (uint32_t)mcp2515_initialize_basic(
            &g_mcp2515_driver,
            MCP2515_CNF1,
            MCP2515_CNF2,
            MCP2515_CNF3,
            true
        );

        tx_frame.arbitration_id = 0x321U;
        tx_frame.dlc = UDS_CAN_MAX_DATA_LENGTH;
        tx_frame.data[0] = 0x02U;
        tx_frame.data[1] = 0x50U;
        tx_frame.data[2] = 0x03U;
        tx_frame.data[3] = 0xA5U;
        tx_frame.data[4] = 0x5AU;
        tx_frame.data[5] = 0x00U;
        tx_frame.data[6] = 0x00U;
        tx_frame.data[7] = 0x00U;

        if (g_board_loopback_init_status == MCP2515_STATUS_OK) {
            g_board_loopback_tx_status = (uint32_t)mcp2515_send_frame(
                &g_mcp2515_driver,
                &tx_frame
            );
            nrf_delay_ms(10U);
            g_board_loopback_rx_status = (uint32_t)mcp2515_try_receive_frame(
                &g_mcp2515_driver,
                &rx_frame
            );
            if (g_board_loopback_rx_status == MCP2515_STATUS_OK) {
                g_board_loopback_rx_can_id = rx_frame.arbitration_id;
                g_board_loopback_rx_data_word0 =
                    ((uint32_t)rx_frame.data[0] << 24) |
                    ((uint32_t)rx_frame.data[1] << 16) |
                    ((uint32_t)rx_frame.data[2] << 8) |
                    (uint32_t)rx_frame.data[3];
                g_board_loopback_rx_data_word1 =
                    ((uint32_t)rx_frame.data[4] << 24) |
                    ((uint32_t)rx_frame.data[5] << 16) |
                    ((uint32_t)rx_frame.data[6] << 8) |
                    (uint32_t)rx_frame.data[7];
            }
        }
    }
#endif

    mcp_status = mcp2515_initialize_basic(
        &g_mcp2515_driver,
        MCP2515_CNF1,
        MCP2515_CNF2,
        MCP2515_CNF3,
        false
    );
    g_board_mcp2515_init_status = (uint32_t)mcp_status;
    (void)mcp2515_capture_diagnostics(&g_mcp2515_driver, &mcp_diagnostics);
    g_board_mcp2515_canstat = mcp_diagnostics.canstat;
    g_board_mcp2515_canctrl = mcp_diagnostics.canctrl;
    g_board_mcp2515_read_status = mcp_diagnostics.read_status;
    g_board_mcp2515_canstat_read_status = (uint32_t)mcp_diagnostics.read_canstat_status;
    g_board_mcp2515_canctrl_read_status = (uint32_t)mcp_diagnostics.read_canctrl_status;
    g_board_mcp2515_status_read_status = (uint32_t)mcp_diagnostics.read_status_status;

    if (mcp_status != MCP2515_STATUS_OK) {
        board_log_printf(
            "[BOOT][MCP2515] init failed status=%u canstat=0x%02X/%u canctrl=0x%02X/%u read_status=0x%02X/%u\n",
            (unsigned)mcp_status,
            (unsigned)mcp_diagnostics.canstat,
            (unsigned)mcp_diagnostics.read_canstat_status,
            (unsigned)mcp_diagnostics.canctrl,
            (unsigned)mcp_diagnostics.read_canctrl_status,
            (unsigned)mcp_diagnostics.read_status,
            (unsigned)mcp_diagnostics.read_status_status
        );
        for (;;) {
            if (NRF_LOG_PROCESS() == false) {
                __WFE();
            }
        }
    }

    mcp2515_can_port_init(
        &g_can_port,
        &g_mcp2515_can_port_context,
        &g_mcp2515_driver
    );
    uds_board_runtime_init(
        &g_board_runtime,
        &g_board_adapter,
        &g_can_port,
        true
    );
    g_board_task_context.runtime = &g_board_runtime;
    g_board_task_context.idle_delay_ticks = UDS_TASK_IDLE_DELAY_TICKS;
    g_board_task_context.delay_hook = board_runtime_delay_hook;
    g_board_task_context.delay_context = NULL;
}

#if (BOARD_CAN_STARTUP_TEST_FRAME_ENABLED == 1)
static void board_send_startup_test_frame(void)
{
    uds_can_frame_t frame;
    mcp2515_status_t status;

    nrf_delay_ms(BOARD_CAN_STARTUP_TEST_FRAME_DELAY_MS);

    frame.arbitration_id = BOARD_UDS_EXTERNAL_RESPONSE_CAN_ID;
    frame.dlc = UDS_CAN_MAX_DATA_LENGTH;
    frame.data[0] = 0x02U;
    frame.data[1] = 0x50U;
    frame.data[2] = 0x03U;
    frame.data[3] = 0x00U;
    frame.data[4] = 0x00U;
    frame.data[5] = 0x00U;
    frame.data[6] = 0x00U;
    frame.data[7] = 0x00U;

    g_board_startup_test_tx_attempt_count++;
    status = mcp2515_send_frame(&g_mcp2515_driver, &frame);
    g_board_startup_test_tx_last_status = (uint32_t)status;
    if (status == MCP2515_STATUS_OK) {
        g_board_startup_test_tx_ok_count++;
        board_log_printf(
            "[BOOT][CAN] startup test frame queued can_id=0x%03X\n",
            BOARD_UDS_EXTERNAL_RESPONSE_CAN_ID
        );
    } else {
        board_log_printf(
            "[BOOT][CAN] startup test frame failed status=%u\n",
            (unsigned)status
        );
    }
}
#endif

int main(void)
{
    board_clock_init();
    board_logs_init();

    board_log_printf(
        "[BOOT] hotpatch UDS board baseline starting profile=%s\n",
        BOARD_BASELINE_PROFILE_NAME
    );

    if (!board_wiring_configured()) {
        board_log_printf(
            "[BOOT] MCP2515 pins are not configured. Set MCP2515_SPI_* macros before flashing.\n"
        );
        for (;;) {
            if (NRF_LOG_PROCESS() == false) {
                __WFE();
            }
        }
    }

    if (!board_mcp2515_timing_configured()) {
        board_log_printf(
            "[BOOT] MCP2515 CNF timing is not configured. Set MCP2515_CNF1/2/3 before flashing.\n"
        );
        for (;;) {
            if (NRF_LOG_PROCESS() == false) {
                __WFE();
            }
        }
    }

    board_spim_init();
    board_diag_runtime_init();

    board_log_printf(
        "[BOOT] gateway route ext=0x%03X/0x%03X -> int=0x%03X/0x%03X profile=%s gateway_mode=%d ecu=%s hotpatch=%u kintsugi=%u can=%lu@%luHz task_prio=%u\n",
        BOARD_UDS_EXTERNAL_REQUEST_CAN_ID,
        BOARD_UDS_EXTERNAL_RESPONSE_CAN_ID,
        BOARD_UDS_INTERNAL_REQUEST_CAN_ID,
        BOARD_UDS_INTERNAL_RESPONSE_CAN_ID,
        BOARD_BASELINE_PROFILE_NAME,
        (int)BOARD_UDS_GATEWAY_MODE,
        BOARD_UDS_ECU_PROFILE_NAME,
        (unsigned)BOARD_UDS_APPLY_SECURITY_ACCESS_HOTPATCH,
        (unsigned)BOARD_UDS_KINTSUGI_BRIDGE_ENABLED,
        (unsigned long)BOARD_CAN_BITRATE_BPS,
        (unsigned long)BOARD_MCP2515_OSCILLATOR_HZ,
        (unsigned)UDS_TASK_PRIORITY
    );

#if (BOARD_CAN_STARTUP_TEST_FRAME_ENABLED == 1)
    board_send_startup_test_frame();
#endif

    APP_ERROR_CHECK(
        xTaskCreate(
            uds_board_freertos_task,
            "UDS_DIAG",
            UDS_TASK_STACK_SIZE,
            &g_board_task_context,
            UDS_TASK_PRIORITY,
            NULL
        ) == pdPASS ? NRF_SUCCESS : NRF_ERROR_NO_MEM
    );

    vTaskStartScheduler();

    for (;;) {
    }
}
