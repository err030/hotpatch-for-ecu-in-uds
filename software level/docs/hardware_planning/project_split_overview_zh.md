# Project Split Overview

当前仓库现在按两条主线拆成两个顶层目录：

- `software level/`
  软件语义、Python baseline、测试、图表和软件侧文档。
- `hardware level/`
  只放硬件侧 C 工程内容，包括头文件、源文件、链接脚本、补丁和 Makefile。

## 为什么这样拆

如果把板级 bring-up、FreeRTOS/Kintsugi 集成和 Python 仿真继续混在一起，后面会把四件事情搅在同一个工作区里：

- 软件语义验证
- 攻击路径仿真与评估
- 板级环境构造
- C 版 UDS 固件实现

现在拆完以后：

- `software level/` 继续负责“行为模型、验证和评估”
- `hardware level/` 只负责“板级落地和 C 实现”

## 当前目录落点

- `software level/src/`
  当前可运行的 Python UDS/hotpatch 实现。
- `software level/tests/`
  Python 基线测试。
- `software level/charts/`
  图表和报告素材。
- `software level/archive/`
  单独归档的一份 Python baseline 副本。
- `software level/docs/software_baseline/`
  软件侧盘点和说明文档。
- `software level/docs/hardware_planning/`
  硬件侧迁移、Kintsugi 集成、规则说明文档。
- `hardware level/app/`
  预留给后续自写的 ECU firmware C 模块。
- `hardware level/board_baseline/`
  `nRF52840 + FreeRTOS` 起步底座。
- `hardware level/third_party/kintsugi_minimal/`
  当前复制进仓库的 `measurement-free` Kintsugi 最小组件集。

## 当前判断

- 如果目标是继续跑 Python 仿真、评估和论文图表，主工作区在 `software level/`。
- 如果目标是接板、接 `FreeRTOS`、接 `Kintsugi`，主工作区在 `hardware level/`。
- 所有硬件方向说明文档统一放在 `software level/docs/hardware_planning/`，避免 `hardware level/` 混入非 C 内容。
