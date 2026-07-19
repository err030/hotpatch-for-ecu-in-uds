# Fleet OTA Exposure Simulation References

This simulation is a lightweight discrete-event fleet rollout model. It does not import a traffic simulator directly because the thesis metric is a security exposure window, not route choice or passenger assignment.

Open-source projects used as modeling references:

- Eclipse SUMO: open-source microscopic traffic simulation for large road networks. Useful as context for traffic-scale simulation, but not used here because OTA security exposure does not require road-network dynamics.
- FleetPy: open-source fleet simulation framework for vehicle fleets, routing, user assignment, charging, and demand-responsive services. Useful as a fleet/agent reference, but too broad for this UDS security metric.
- UXsim: lightweight Python macro/mesoscopic traffic flow simulator. Useful evidence that large-scale vehicle simulation can be abstracted efficiently, but its traffic-flow model is orthogonal to OTA exposure.
- python-can and python-udsoncan: CAN/UDS protocol references already aligned with the lower-level part of this project.

Metric definition:

- A vehicle is vulnerable until either the full OTA update finishes or a hotpatch-first guard finishes.
- Cumulative exposure is the sum of vulnerable minutes across all vehicles.
- Expected successful attack opportunities multiply exposure vehicle-days by an assumed attack-attempt rate and by the measured UDS 0x2E hardware fuzzing pass rate.
