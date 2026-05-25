# App Layout

这里说明的是 `hardware level/app/` 这块预留区域。这个目录只给后续板上 `UDS ECU firmware` 的自有 C 模块使用，不放 Python、不放文档。

建议后续拆分为：

- `hardware level/app/include/`
  对外头文件。
- `hardware level/app/src/`
  `session_state / uds_dispatcher / config_table / did_write / replay_check` 等业务模块。

当前还没有把这些业务模块补进去，先把目录边界和第三方依赖边界定住。
