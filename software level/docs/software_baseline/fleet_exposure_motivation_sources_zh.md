# Fleet Exposure Motivation Sources

## 这部分要证明什么

论文开头可以拆成两层论证：

1. **暴露窗口本身很大**  
   完整 OTA 受车辆可用窗口、后台更新资源、更新安全条件、用户/运营调度影响。这个结论不依赖攻击成功概率。

2. **暴露窗口乘以实测攻击概率后，安全风险仍然显著**  
   本项目硬件 fuzzing 得到 `0x2E` 攻击 pass rate 为 `77.4%`。将该概率乘到 fleet exposure 后，可以得到期望成功攻击机会。

## 公开资料能支持什么

### UNECE R155 / R156

可支持：

- 现代联网车辆需要 Cyber Security Management System 和 Software Update Management System；
- 软件更新需要系统化开发、验证、发布流程；
- OTA 更新需要考虑安全条件、失败回滚/安全状态、电量、更新期间不可用功能、用户提示等；
- 因此 OTA 不是“漏洞发现后瞬间全车队完成”的过程。

不能支持：

- 某家车厂真实 fleet update rollout 需要几小时或几天；
- 商业车队每辆车真实维护窗口分布。

原因是这些属于厂商/运营商内部调度和商业数据，公开文件通常不会披露。

### FleetPy / SUMO / UXsim

可支持：

- 车队级问题通常用仿真研究，因为真实 fleet 实验成本高；
- vehicle availability、operator resource、time-series metrics 是合理抽象；
- 用轻量离散事件模型估计 fleet-level exposure 是合理的 thesis 方法。

不能支持：

- UDS 漏洞本身；
- OTA 安全机制本身。

### ScalOTA / Uptane / automotive OTA 文献

可支持：

- OTA 更新涉及分发架构、带宽、延迟、信任链和安全发布；
- OTA 的瓶颈不只在车端 ECU，还包括后端、网络、下载、验证和安装。

## 当前模拟结果如何使用

第一张图：

```text
fig_fleet_exposure_window_only_20260620_default_1000v_60d.pdf
```

只说明暴露窗口大小：

- OTA-only: `9535.43 vehicle-days`
- Hotpatch-first: `2965.14 vehicle-days`
- reduction: `68.90%`
- OTA-only 80% protection: `359.70 h`
- Hotpatch-first 80% protection: `16.45 h`

第二张图：

```text
fig_fleet_attack_weighted_exposure_20260620_default_1000v_60d.pdf
```

在暴露窗口基础上乘入硬件 fuzzing pass rate `0.774`：

- OTA-only expected successful attack opportunities: `369.02`
- Hotpatch-first expected successful attack opportunities: `114.75`

## 论文表述建议

可以这样写：

> Public regulations and OTA update frameworks indicate that vehicle software updates require controlled rollout, validation, safe installation conditions, rollback handling, and user/operator coordination. Since commercial fleet maintenance windows are rarely public, this thesis uses a lightweight discrete-event fleet simulation inspired by open-source fleet/traffic simulators to estimate the security exposure window. The result is not a claim about a specific manufacturer; it is a parameterized estimate of how long vehicles remain vulnerable before protection reaches the fleet.

然后接：

> Under the default 1000-vehicle setting, OTA-only accumulates 9535.43 vehicle-days of exposure before protection reaches the fleet, whereas hotpatch-first reduces this to 2965.14 vehicle-days. When weighted by the measured hardware UDS `0x2E` attack pass rate of 77.4%, the expected successful attack opportunities are reduced from 369.02 to 114.75.

## 建议引用

- UNECE UN Regulation No. 155, Cyber security and cyber security management system.
- UNECE UN Regulation No. 156, Software update and software updates management system.
- ISO 24089, Road vehicles - Software update engineering.
- Kuppusamy et al., Uptane: Securing Software Updates for Automobiles.
- Shoker et al., ScalOTA: Scalable Secure Over-the-Air Software Updates for Vehicles.
- Engelhardt et al., FleetPy: A Modular Open-Source Simulation Tool for Mobility On-Demand Services.
- Eclipse SUMO open-source traffic simulation.
- UXsim open-source Python traffic flow simulator.

