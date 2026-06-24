# Fleet OTA Exposure Window Simulation

## 目的

这个软件层模拟用于支撑论文 motivation：

- 单车硬件实验证明了 UDS `0x27 -> 0x2E` 攻击链在 hotpatch 前可成功；
- 但车队场景下，完整 OTA 往往受车辆在线时间、停车窗口、后台并发资源限制；
- 因此需要度量在完整 OTA 完成前，整个车队累计暴露了多久。

这里的核心指标不是交通效率，而是安全暴露窗口。

## 开源项目参考

调研后，适合作为背景引用，但不适合直接作为当前实现依赖：

- Eclipse SUMO: `https://github.com/eclipse-sumo/sumo`
  - 强项是大规模路网微观交通仿真；
  - 本实验不需要道路、路径、拥堵模型。
- FleetPy: `https://github.com/TUM-VT/FleetPy`
  - 强项是 vehicle fleet 的 agent-based 运营、派单、充电、路由；
  - 当前问题只需要 OTA/hotpatch rollout 的策略级离散事件模型。
- UXsim: `https://github.com/toruseo/UXsim`
  - 强项是轻量 Python 交通流仿真；
  - 可作为大规模车辆仿真的开源参考，但不直接建模 OTA 安全窗口。
- python-can / python-udsoncan:
  - 与底层 CAN/UDS 实验一致；
  - 不负责 fleet rollout 建模。

因此当前实现采用轻量离散事件模拟，避免把论文范围扩展到交通流或车队运营优化。

## 模型假设

默认运行：

- `fleet_size = 1000`
- `horizon = 60 days`
- `ota_slots = 20`
- `hotpatch_slots = 120`
- `ota_duration = 45 min`
- `hotpatch_duration = 3 min`
- `hotpatch_capable_ratio = 0.85`
- 每辆车每天有多个短可用窗口和一个夜间较长窗口
- 攻击成功概率来自硬件 fuzzing 结果：`0.774`

车辆在以下时间点之前视为 vulnerable：

- OTA-only：完整 OTA 完成前；
- hotpatch-first：hotpatch guard 完成前，若车辆不支持 hotpatch，则完整 OTA 完成前。

## 输出文件

脚本：

```bash
python3 "software level/tools/run_fleet_ota_exposure_simulation.py" \
  --tag 20260620_default_1000v_60d
```

结果：

- `software level/charts/fleet_ota_exposure_20260620_default_1000v_60d_summary.csv`
- `software level/charts/fleet_ota_exposure_20260620_default_1000v_60d_actions.csv`
- `software level/charts/fleet_ota_exposure_20260620_default_1000v_60d_vehicles.csv`
- `software level/charts/fleet_ota_exposure_20260620_default_1000v_60d_timeseries.csv`
- `software level/thesis_figures/pdf/fleet_ota_exposure_20260620_default_1000v_60d.pdf`

## 当前结果

默认 1000 车模拟结果：

| Strategy | Cumulative exposure | Full protection | 80% protection | Expected successful attack opportunities |
|---|---:|---:|---:|---:|
| OTA-only | 9535.43 vehicle-days | 456.12 h | 359.70 h | 369.02 |
| Hotpatch-first | 2965.14 vehicle-days | 456.12 h | 16.45 h | 114.75 |

暴露窗口降低：

```text
1 - 2965.14 / 9535.43 = 68.90%
```

解释：

- full protection 时间相同，是因为两种策略最后都仍需完成完整 OTA；
- hotpatch-first 的关键优势是显著提前提供安全保护；
- 在默认参数下，80% 车辆从 OTA-only 的约 `359.70 h` 降到 hotpatch-first 的约 `16.45 h`；
- 累计暴露从 `9535.43 vehicle-days` 降到 `2965.14 vehicle-days`。

## 论文表述建议

可以写成：

> The fleet-level simulation abstracts the OTA rollout as a discrete-event process constrained by vehicle availability windows and backend update slots. A vehicle is considered exposed until either the full OTA update completes or, in the hotpatch-first strategy, the security guard is installed. Under the default 1000-vehicle setting, OTA-only accumulates 9535.43 vehicle-days of exposure, while hotpatch-first reduces this to 2965.14 vehicle-days. This corresponds to a 68.90% reduction in cumulative exposure, while also moving 80% fleet protection from 359.70 h to 16.45 h after vulnerability disclosure.

