# Python Baseline Bundle

这个文件夹是当前 `software level` Python 内容的一份单独打包副本。

## 目的

- 不删除、不移动现有根目录下的 `src/`、`tests/`、`charts/`
- 额外留一份“单独归档”的 software baseline
- 让后续 `hardware level` 工作完全在别的目录推进，不再碰这套 Python 基线

## 内容

- `src/hotpatch_uds/`
  software-first 的 UDS / gateway / hotpatch / timing / evaluation Python 实现副本
- `tests/`
  对应 Python 基线测试副本
- `charts/`
  software-only 评估与图表脚本/结果副本
- `docs/`
  当前 Python baseline 相关的顶层说明文档副本

## 说明

- 这是“归档副本”，不是新的主开发入口
- 当前主 Python 代码仍在仓库根目录 `src/` 与 `tests/`
- `hardware level` 只复用这里的思路、规则和方法，不直接复用 Python 源码
