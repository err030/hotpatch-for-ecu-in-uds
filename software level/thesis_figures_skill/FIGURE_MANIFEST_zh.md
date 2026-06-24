# Skill-Generated Thesis Figures

这些图由 `generate_skill_figures.py` 生成，使用 Python/matplotlib 后端。
本版按照 IoT / software-security 论文图的读图方式重构：先定义图要证明的结论，再选择 flow、sequence、matrix、scatter、area、scorecard 等图型。

## Figure Contract

- Core conclusion: Kintsugi runtime hotpatching changes the ECU-local UDS policy without replacing the diagnostic path.
- Evidence chain: architecture/data path -> UDS attack chain -> mutation/control -> runtime lifecycle -> hardware observer -> fleet exposure -> real can0 trace -> thesis scorecard.
- Archetype: schematic-led composite plus quantitative support panels.
- Export: PDF for LaTeX, SVG for editable text.
- Review risk: rates and fleet exposure are artifact-derived; captions should state corpus size and simulation assumptions.

## Outputs

- `fig01_skill_architecture_lifecycle`: `thesis_figures_skill/pdf/fig01_skill_architecture_lifecycle.pdf` / `thesis_figures_skill/svg/fig01_skill_architecture_lifecycle.svg`
- `fig02_skill_uds_attack_chain`: `thesis_figures_skill/pdf/fig02_skill_uds_attack_chain.pdf` / `thesis_figures_skill/svg/fig02_skill_uds_attack_chain.svg`
- `fig03_skill_mutation_control_group`: `thesis_figures_skill/pdf/fig03_skill_mutation_control_group.pdf` / `thesis_figures_skill/svg/fig03_skill_mutation_control_group.svg`
- `fig04_skill_kintsugi_during_lifecycle`: `thesis_figures_skill/pdf/fig04_skill_kintsugi_during_lifecycle.pdf` / `thesis_figures_skill/svg/fig04_skill_kintsugi_during_lifecycle.svg`
- `fig05_skill_hardware_observer_validation`: `thesis_figures_skill/pdf/fig05_skill_hardware_observer_validation.pdf` / `thesis_figures_skill/svg/fig05_skill_hardware_observer_validation.svg`
- `fig06_skill_fleet_exposure_risk`: `thesis_figures_skill/pdf/fig06_skill_fleet_exposure_risk.pdf` / `thesis_figures_skill/svg/fig06_skill_fleet_exposure_risk.svg`
- `fig07_skill_can0_request_timeline`: `thesis_figures_skill/pdf/fig07_skill_can0_request_timeline.pdf` / `thesis_figures_skill/svg/fig07_skill_can0_request_timeline.svg`
- `fig08_skill_evidence_chain_summary`: `thesis_figures_skill/pdf/fig08_skill_evidence_chain_summary.pdf` / `thesis_figures_skill/svg/fig08_skill_evidence_chain_summary.svg`

## Source Data

- `software level/charts/uds_2e_mutation_attack_summary.csv`
- `software level/charts/uds_control_group_summary.csv`
- `software level/charts/uds_kintsugi_during_lifecycle_latest.csv`
- `software level/charts/hardware_uds_2e_fuzz_observer_20260620_uds2e_1000_observer_detail.csv`
- `software level/charts/fleet_ota_exposure_20260620_default_1000v_60d_summary.csv`
- `software level/charts/can0_request_timeline_latest.csv`
- `software level/charts/can0_request_timeline_kintsugi_after_latest.csv`
