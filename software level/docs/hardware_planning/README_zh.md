# Hardware Planning

这里集中放 `hardware level` 方向的说明文档。真正的板级代码不放在这里，而是放在仓库根目录的 `hardware level/`，这样可以保证 `hardware level/` 里只保留 C 相关实现、头文件、链接脚本、补丁和构建文件。

## 当前边界

- `software level/`
  Python baseline、测试、图表和软件侧说明文档。
- `software level/docs/hardware_planning/`
  板级迁移说明、Kintsugi 组件取舍、接口语义和缺口清单。
- `hardware level/`
  只放硬件侧 C 工程内容。

## 主要文档入口

- [project_split_overview_zh.md](project_split_overview_zh.md)
  当前仓库为什么拆成 `software level` 和 `hardware level`。
- [reuse_inventory_zh.md](reuse_inventory_zh.md)
  旧 `kintsugi_artifact_zenodo` 里哪些资产值得复用。
- [implementation_gap_checklist_zh.md](implementation_gap_checklist_zh.md)
  按 `环境构造 / FreeRTOS 工程 / RTT / Config Table / Session 状态机 / UDS Dispatcher / DID Write / Replay Check` 逐项列缺口。
- [kintsugi_uds_hotpatch_integration_zh.md](kintsugi_uds_hotpatch_integration_zh.md)
  为了把 `attack entry -> ECU -> Kintsugi hotpatch` 接起来，到底要引哪些 Kintsugi 组件。
- [app_layout_zh.md](app_layout_zh.md)
  `hardware level/app/` 预留模块的建议拆分。
- [kintsugi_minimal_bundle_zh.md](kintsugi_minimal_bundle_zh.md)
  当前仓库已经复制进来的 `measurement-free` Kintsugi 最小集说明。

## 对应的代码位置

- `hardware level/app/`
  后续你自己写的 `UDS ECU firmware` C 模块。
- `hardware level/board_baseline/`
  从旧工程提炼出来的 `nRF52840 + FreeRTOS` 起步底座。
- `hardware level/third_party/kintsugi_minimal/`
  当前最小化保留的 Kintsugi 运行时组件。

## 当前结论

- software 和 hardware 现在已经物理分开。
- `hardware level/` 不再承载 Markdown 说明文件。
- Python 语义模型继续保留在 `software level/`，硬件实现只复用其中的方法和规则，不再混放代码。
