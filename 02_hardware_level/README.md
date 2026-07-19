# Hardware prototype

This folder contains the two boards used for the hardware evaluation.

- `board_baseline/`: the nRF52840 ECU prototype with FreeRTOS and an MCP2515 CAN controller
- `app/`: shared UDS, gateway, ECU, and MCP2515 source code
- `nucleo_g474re_can_observer/`: a Nucleo-G474RE that listens to the CAN traffic and writes UART logs

The CAN bus runs at 250 kbit/s. The tester request ID is `0x7E0` and the ECU response ID is `0x7E8`.

## Hardware used

- Nordic nRF52840 DK
- MCP2515 CAN module
- CANable 2.0 or another SocketCAN adapter
- Nucleo-G474RE with an SN65HVD230 transceiver for passive observation
- two 120 ohm terminators, one at each end of the CAN bus

The Nucleo observer is useful for evaluation, but the nRF52840 prototype can run without it.

## Build the nRF52840 firmware

Install the tools listed in `requirements.txt`. From the repository root, run:

```bash
cd 02_hardware_level/board_baseline
make secure
```

The main build profiles are:

- `vulnerable`: the request reaches a vulnerable ECU
- `secure`: the gateway is permissive, but the ECU applies its strict policy
- `gateway-secure`: the gateway blocks the protected request
- `hotpatched`: the ECU-local patch policy is already active
- `kintsugi-runtime`: Kintsugi activates the ECU-local policy during runtime

For the Kintsugi runtime profile, the control request `0x2E F190 01` starts the patch lifecycle. The applied policy sets `quarantine_config_write_did = true` and blocks the protected configuration write.

Build and flash one profile with, for example:

```bash
make flash-vulnerable
make flash-kintsugi-runtime
```

Connect RTT Viewer or another SEGGER RTT client to read the firmware log.

## Prepare `can0` on Linux

The bitrate must match the firmware:

```bash
sudo ip link set can0 down 2>/dev/null || true
sudo ip link set can0 type can bitrate 250000
sudo ip link set can0 up
candump can0
```

The attack and measurement scripts are in `01_software_level/tools/`. Most scripts support `--help`, for example:

```bash
python3 01_software_level/tools/uds_2e_security_access_attack_test.py --help
```

Run this command from the repository root.

## Nucleo observer

The observer should use `BUS_MONITORING` for the final experiment, so it does not send CAN frames or ACKs:

```bash
cd 02_hardware_level/nucleo_g474re_can_observer
make FDCAN_MODE=BUS_MONITORING FDCAN_BITRATE=250000
```

See `nucleo_g474re_can_observer/README_zh.md` for wiring, flashing, and UART log details.

## Important limitation

The firmware is a bachelor-thesis prototype. It demonstrates a policy-based defense on the Kintsugi runtime. It is not a complete production ECU or a general-purpose Kintsugi port.
