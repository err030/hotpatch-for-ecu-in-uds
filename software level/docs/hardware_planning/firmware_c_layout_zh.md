# Firmware C Layout

这里说明的是仓库根目录 `hardware level/` 这块代码区，只放 `C / linker / patch / board baseline` 相关内容。

## 目录

- `app/`
  预留给你后续自己写的 `UDS ECU firmware`，现在还没有把业务代码塞进来。
- `board_baseline/`
  从旧 `before_patching` 提取的最小板级入口文件。
- `third_party/kintsugi_minimal/`
  从旧 `Kintsugi` 复制出来、去掉 `measurement` 必需依赖后的最小组件集。

## 原则

- 不直接改根目录 `src/` 的 Python 实现
- hardware 里只放 `C` 代码和硬件工程材料
- 需要参考 software level 时，参考的是方法、状态机和规则，不是直接引用 Python 文件
- 规则说明文档统一放在 `software level/docs/hardware_planning/`，不再放进 `hardware level/`
