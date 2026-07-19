# Software-level model and test tools

This folder contains the Python model used before testing the real CAN hardware. It models a UDS tester, gateway, ECU, ISO-TP messages, attacks, and the policy applied by the hotpatch.

The normal unit tests do not need CAN hardware. Linux is only needed for the `vcan0` and SocketCAN tests.

## Quick start

Run these commands from this folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m src.hotpatch_uds.main
python3 -m unittest discover -s tests -v
```

The main command prints a short comparison of the vulnerable and patched behavior. The tests check the protocol model, gateway rules, attack cases, fuzzing, timing model, and fleet model.

## Main folders

```text
src/hotpatch_uds/  Python model of the UDS system
tests/             unit and integration tests
tools/             data collection and analysis scripts
results/           saved software and hardware measurements
```

Important modules in `src/hotpatch_uds/` are:

- `protocol.py`: UDS request and response handling
- `ecu.py`: vulnerable, secure, and patchable ECU behavior
- `gateway.py`: diagnostic routing and gateway policy
- `hotpatch.py`: small software model of the Kintsugi-style patch policy
- `pythoncan.py` and `socketcan.py`: optional CAN backends
- `fleet.py`: OTA-only and hotpatch-first fleet simulation

## Optional virtual CAN test

On Linux, create `vcan0` first:

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set vcan0 up
python3 -m unittest tests.test_socketcan tests.test_pythoncan -v
```

The in-memory tests and the `python-can` virtual backend can run without `vcan0`. macOS can run the normal unit tests, but it cannot provide Linux SocketCAN.

## Recreate the thesis figures

Run these commands from the repository root:

```bash
python3 05_evaluation/thesis_figures/generate_figures.py
python3 05_evaluation/thesis_figures/generate_evaluation_tables.py
python3 05_evaluation/thesis_figures/validate_figures.py
```

The figure scripts read the saved files in `results/`. They do not require the hardware to be connected. See `results/README_zh.md` for notes about the recorded data.

## Real CAN tools

The scripts in `tools/` can collect data from `can0` and from the Nucleo observer. They need Linux, configured CAN hardware, and the correct serial device path. Do not use them for a first software-only run.

The hardware setup is described in `../02_hardware_level/README.md`.
