# Thesis PDF Figure Manifest

输出目录：`software level/thesis_figures/pdf/`

| File | Suggested chapter | Purpose |
|---|---|---|
| `fig01_system_architecture.pdf` | System Design | 总体硬件/软件工作流 |
| `fig02_uds_attack_sequence.pdf` | Threat Model / Attack Design | UDS 0x27 -> 0x2E 攻击链 |
| `fig03_gateway_defense_boundary.pdf` | Design Rationale | gateway 与 ECU-local hotpatch 边界 |
| `fig04_kintsugi_hotpatch_lifecycle.pdf` | Implementation | Kintsugi runtime hotpatch 流程 |
| `fig05_mutation_attack_success_rate.pdf` | Evaluation | hotpatch 前后攻击成功率 |
| `fig06_mutation_corpus_breakdown.pdf` | Evaluation | mutation corpus 组成，解释为何前置成功率不是 100% |
| `fig07_hardware_validation_matrix.pdf` | Evaluation | 硬件 profile 验证矩阵 |
| `fig08_timing_overhead.pdf` | Evaluation | latency / jitter 开销 |
| `fig09_hotpatch_resource_footprint.pdf` | Evaluation | hotpatch 内存资源占用 |
| `fig10_fleet_exposure_reduction.pdf` | Discussion / Evaluation | fleet-level exposure model |
| `fig11_control_group_success_rates.pdf` | Evaluation | 普通诊断请求对照组与攻击 mutation 对比 |

LaTeX 示例：

```latex
\includegraphics[width=0.92\linewidth]{\detokenize{software level/thesis_figures/pdf/fig05_mutation_attack_success_rate.pdf}}
```

Generated files:

- `fig01_system_architecture.pdf`
- `fig02_uds_attack_sequence.pdf`
- `fig03_gateway_defense_boundary.pdf`
- `fig04_kintsugi_hotpatch_lifecycle.pdf`
- `fig05_mutation_attack_success_rate.pdf`
- `fig06_mutation_corpus_breakdown.pdf`
- `fig07_hardware_validation_matrix.pdf`
- `fig08_timing_overhead.pdf`
- `fig09_hotpatch_resource_footprint.pdf`
- `fig10_fleet_exposure_reduction.pdf`
- `fig11_control_group_success_rates.pdf`
