# Hotpatch defense for an ECU over UDS

This repository is the prototype and evaluation code for a bachelor thesis. It studies a policy-based defense for a UDS configuration-write attack. The defense is applied through the Kintsugi hotpatch runtime instead of replacing the full ECU firmware.

The easiest way to understand the project is:

```text
UDS tester -> gateway -> ECU
                         |
                         +-> Kintsugi activates a policy that blocks the unsafe write
```

## Repository layout

```text
01_software_level/  Python model, tests, experiment tools, and saved results
02_hardware_level/  nRF52840 ECU prototype and Nucleo CAN observer
03_hotpatches/      example patch source files
04_kintsugi/        Kintsugi runtime used by the prototype
05_evaluation/      scripts and final figures for the thesis
external/           nRF5 SDK and FreeRTOS source code
```

## Start without hardware

Python 3 is enough for the basic model. From the repository root, run:

```bash
cd 01_software_level
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m src.hotpatch_uds.main
python3 -m unittest discover -s tests -v
```

This works on macOS and Linux. The Linux `vcan0` tests and real `can0` measurements are optional.

## Recreate the evaluation figures

The measured data is already stored in the repository. Hardware is not needed to recreate the figures. Open a terminal in the repository root and run:

```bash
python3 05_evaluation/thesis_figures/generate_figures.py
python3 05_evaluation/thesis_figures/generate_evaluation_tables.py
python3 05_evaluation/thesis_figures/validate_figures.py
```

## Use the hardware prototype

Read `02_hardware_level/README.md` before building or flashing a board. It lists the hardware, build profiles, CAN settings, and the role of the Nucleo observer.

The thesis contains the full design and evaluation. These README files only explain how the repository is arranged and how to run the main parts.
