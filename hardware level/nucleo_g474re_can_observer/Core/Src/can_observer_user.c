#include "can_observer_user.h"

#include "main.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern FDCAN_HandleTypeDef hfdcan1;
#if !defined(NUCLEO_OBSERVER_CAN_LED_TEST) && !defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
extern UART_HandleTypeDef huart2;
#endif

#define OBSERVER_CAN_ID_REQUEST  0x7E0U
#define OBSERVER_CAN_ID_RESPONSE 0x7E8U

#if defined(NUCLEO_OBSERVER_CAN_LED_TEST)
static volatile uint32_t observer_led_pulse_until_ms;
#elif defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
static uint32_t observer_poll_led_pulse_until_ms;
#endif

static void observer_uart_write(const char *line)
{
#if defined(NUCLEO_OBSERVER_CAN_LED_TEST) || defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
    (void)line;
#else
    (void)HAL_UART_Transmit(
        &huart2,
        (uint8_t *)line,
        (uint16_t)strlen(line),
        HAL_MAX_DELAY
    );
#endif
}

#if !defined(NUCLEO_OBSERVER_CAN_LED_TEST) && !defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
#define OBSERVER_RING_SIZE 64U

typedef struct {
    uint32_t timestamp_us;
    uint32_t can_id;
    uint8_t dlc;
    uint8_t data[8];
} observer_frame_t;

static observer_frame_t observer_ring[OBSERVER_RING_SIZE];
static volatile uint16_t observer_head;
static volatile uint16_t observer_tail;
static volatile uint32_t observer_dropped_frames;
static uint32_t observer_cycles_per_us = 1U;

static uint8_t fdcan_dlc_to_bytes(uint32_t data_length)
{
    switch (data_length) {
    case FDCAN_DLC_BYTES_0: return 0U;
    case FDCAN_DLC_BYTES_1: return 1U;
    case FDCAN_DLC_BYTES_2: return 2U;
    case FDCAN_DLC_BYTES_3: return 3U;
    case FDCAN_DLC_BYTES_4: return 4U;
    case FDCAN_DLC_BYTES_5: return 5U;
    case FDCAN_DLC_BYTES_6: return 6U;
    case FDCAN_DLC_BYTES_7: return 7U;
    case FDCAN_DLC_BYTES_8: return 8U;
    default: return 8U;
    }
}

static uint32_t observer_micros(void)
{
    return DWT->CYCCNT / observer_cycles_per_us;
}

static void observer_dwt_init(void)
{
    observer_cycles_per_us = SystemCoreClock / 1000000U;
    if (observer_cycles_per_us == 0U) {
        observer_cycles_per_us = 1U;
    }

    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0U;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

static void observer_enqueue(uint32_t can_id, uint8_t dlc, const uint8_t *data)
{
    uint16_t head = observer_head;
    uint16_t next = (uint16_t)((head + 1U) % OBSERVER_RING_SIZE);

    if (next == observer_tail) {
        observer_dropped_frames++;
        return;
    }

    observer_ring[head].timestamp_us = observer_micros();
    observer_ring[head].can_id = can_id;
    observer_ring[head].dlc = dlc;
    memset(observer_ring[head].data, 0, sizeof(observer_ring[head].data));
    if (dlc > 0U) {
        memcpy(observer_ring[head].data, data, dlc > 8U ? 8U : dlc);
    }

    observer_head = next;
}

static bool observer_dequeue(observer_frame_t *frame_out)
{
    uint16_t tail;

    if (frame_out == NULL || observer_tail == observer_head) {
        return false;
    }

    __disable_irq();
    if (observer_tail == observer_head) {
        __enable_irq();
        return false;
    }

    tail = observer_tail;
    *frame_out = observer_ring[tail];
    observer_tail = (uint16_t)((tail + 1U) % OBSERVER_RING_SIZE);
    __enable_irq();

    return true;
}

static void observer_format_and_send(const observer_frame_t *frame)
{
    char line[96];
    char *cursor = line;
    int remaining = (int)sizeof(line);
    int written;

    written = snprintf(
        cursor,
        (size_t)remaining,
        "MON,%010lu,%03lX,%u,",
        (unsigned long)frame->timestamp_us,
        (unsigned long)frame->can_id,
        (unsigned)frame->dlc
    );
    if (written < 0 || written >= remaining) {
        return;
    }
    cursor += written;
    remaining -= written;

    for (uint8_t i = 0; i < frame->dlc && i < 8U; i++) {
        written = snprintf(cursor, (size_t)remaining, "%02X", frame->data[i]);
        if (written < 0 || written >= remaining) {
            return;
        }
        cursor += written;
        remaining -= written;
    }

    (void)snprintf(cursor, (size_t)remaining, "\r\n");
    observer_uart_write(line);
}

static void observer_drain_rx_fifo(FDCAN_HandleTypeDef *hfdcan)
{
    FDCAN_RxHeaderTypeDef header;
    uint8_t data[8];
    uint8_t dlc;

    while (HAL_FDCAN_GetRxFifoFillLevel(hfdcan, FDCAN_RX_FIFO0) > 0U) {
        memset(data, 0, sizeof(data));
        if (HAL_FDCAN_GetRxMessage(hfdcan, FDCAN_RX_FIFO0, &header, data) != HAL_OK) {
            return;
        }

        if (header.IdType != FDCAN_STANDARD_ID || header.RxFrameType != FDCAN_DATA_FRAME) {
            continue;
        }

        if (header.Identifier != OBSERVER_CAN_ID_REQUEST &&
            header.Identifier != OBSERVER_CAN_ID_RESPONSE) {
            continue;
        }

        HAL_GPIO_TogglePin(LD2_GPIO_Port, LD2_Pin);
        dlc = fdcan_dlc_to_bytes(header.DataLength);
        observer_enqueue(header.Identifier, dlc, data);
    }
}
#endif

static void observer_configure_filters(void)
{
    FDCAN_FilterTypeDef filter = {0};

    filter.IdType = FDCAN_STANDARD_ID;
    filter.FilterIndex = 0U;
#if defined(NUCLEO_OBSERVER_CAN_LED_TEST) || defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
    filter.FilterType = FDCAN_FILTER_MASK;
    filter.FilterConfig = FDCAN_FILTER_TO_RXFIFO0;
    filter.FilterID1 = 0x000U;
    filter.FilterID2 = 0x000U;
#else
    filter.FilterType = FDCAN_FILTER_DUAL;
    filter.FilterConfig = FDCAN_FILTER_TO_RXFIFO0;
    filter.FilterID1 = OBSERVER_CAN_ID_REQUEST;
    filter.FilterID2 = OBSERVER_CAN_ID_RESPONSE;
#endif

    if (HAL_FDCAN_ConfigFilter(&hfdcan1, &filter) != HAL_OK) {
        observer_uart_write("ERR,FDCAN_CONFIG_FILTER\r\n");
        Error_Handler();
    }

    if (HAL_FDCAN_ConfigGlobalFilter(
            &hfdcan1,
            FDCAN_REJECT,
            FDCAN_REJECT,
            FDCAN_REJECT_REMOTE,
            FDCAN_REJECT_REMOTE
        ) != HAL_OK) {
        observer_uart_write("ERR,FDCAN_GLOBAL_FILTER\r\n");
        Error_Handler();
    }
}

void can_observer_init(void)
{
#if !defined(NUCLEO_OBSERVER_CAN_LED_TEST) && !defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
    observer_dwt_init();
    observer_uart_write("BOOT,NUCLEO_G474RE_CAN_OBSERVER,250000,LISTEN_ONLY,RX=IRQ,IDS=7E0/7E8\r\n");
    if (hfdcan1.Init.Mode != FDCAN_MODE_BUS_MONITORING) {
        observer_uart_write("WARN,FDCAN_NOT_BUS_MONITORING_CHECK_CUBEMX\r\n");
    }
#endif

    observer_configure_filters();

    if (HAL_FDCAN_Start(&hfdcan1) != HAL_OK) {
        observer_uart_write("ERR,FDCAN_START\r\n");
        Error_Handler();
    }

    if (HAL_FDCAN_ActivateNotification(
            &hfdcan1,
            FDCAN_IT_RX_FIFO0_NEW_MESSAGE,
            0U
        ) != HAL_OK) {
        observer_uart_write("ERR,FDCAN_NOTIFICATION\r\n");
        Error_Handler();
    }
}

void can_observer_init_polling(void)
{
#if !defined(NUCLEO_OBSERVER_CAN_LED_TEST) && !defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
    observer_dwt_init();
    observer_uart_write("BOOT,NUCLEO_G474RE_CAN_OBSERVER,250000,LISTEN_ONLY,RX=POLLING,IDS=7E0/7E8\r\n");
    if (hfdcan1.Init.Mode != FDCAN_MODE_BUS_MONITORING) {
        observer_uart_write("WARN,FDCAN_NOT_BUS_MONITORING_CHECK_CUBEMX\r\n");
    }
#endif

    observer_configure_filters();

    if (HAL_FDCAN_Start(&hfdcan1) != HAL_OK) {
        Error_Handler();
    }
}

void can_observer_poll_led(void)
{
#if defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
    FDCAN_RxHeaderTypeDef header;
    uint8_t data[8];

    if (observer_poll_led_pulse_until_ms != 0U &&
        (int32_t)(HAL_GetTick() - observer_poll_led_pulse_until_ms) >= 0) {
        HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_RESET);
        observer_poll_led_pulse_until_ms = 0U;
    }

    while (HAL_FDCAN_GetRxFifoFillLevel(&hfdcan1, FDCAN_RX_FIFO0) > 0U) {
        memset(data, 0, sizeof(data));
        if (HAL_FDCAN_GetRxMessage(&hfdcan1, FDCAN_RX_FIFO0, &header, data) != HAL_OK) {
            Error_Handler();
        }

        if (header.IdType == FDCAN_STANDARD_ID && header.RxFrameType == FDCAN_DATA_FRAME) {
            HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_SET);
            observer_poll_led_pulse_until_ms = HAL_GetTick() + 300U;
        }
    }
#else
    return;
#endif
}

void can_observer_poll_uart(void)
{
#if defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
    return;
#elif defined(NUCLEO_OBSERVER_CAN_LED_TEST)
    uint32_t pulse_until = observer_led_pulse_until_ms;

    if (pulse_until != 0U && (int32_t)(HAL_GetTick() - pulse_until) >= 0) {
        HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_RESET);
        observer_led_pulse_until_ms = 0U;
    }
    return;
#else
    observer_frame_t frame;
    uint32_t dropped;
    char line[64];

#if defined(NUCLEO_OBSERVER_CAN_POLL_UART)
    observer_drain_rx_fifo(&hfdcan1);
#endif

    while (observer_dequeue(&frame)) {
        observer_format_and_send(&frame);
    }

    dropped = observer_dropped_frames;
    if (dropped != 0U) {
        __disable_irq();
        observer_dropped_frames = 0U;
        __enable_irq();
        (void)snprintf(line, sizeof(line), "WARN,DROPPED,%lu\r\n", (unsigned long)dropped);
        observer_uart_write(line);
    }
#endif
}

void HAL_FDCAN_RxFifo0Callback(FDCAN_HandleTypeDef *hfdcan, uint32_t rx_fifo0_its)
{
#if defined(NUCLEO_OBSERVER_CAN_LED_TEST) || defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
    FDCAN_RxHeaderTypeDef header;
    uint8_t data[8];
#endif

    if (hfdcan != &hfdcan1 || (rx_fifo0_its & FDCAN_IT_RX_FIFO0_NEW_MESSAGE) == 0U) {
        return;
    }

#if !defined(NUCLEO_OBSERVER_CAN_LED_TEST) && !defined(NUCLEO_OBSERVER_CAN_POLL_LED_TEST)
    observer_drain_rx_fifo(hfdcan);
#else
    while (HAL_FDCAN_GetRxFifoFillLevel(hfdcan, FDCAN_RX_FIFO0) > 0U) {
        memset(data, 0, sizeof(data));
        if (HAL_FDCAN_GetRxMessage(hfdcan, FDCAN_RX_FIFO0, &header, data) != HAL_OK) {
            return;
        }

        if (header.IdType != FDCAN_STANDARD_ID || header.RxFrameType != FDCAN_DATA_FRAME) {
            continue;
        }
#if defined(NUCLEO_OBSERVER_CAN_LED_TEST)
        HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_SET);
        observer_led_pulse_until_ms = HAL_GetTick() + 150U;
#endif
    }
#endif
}
