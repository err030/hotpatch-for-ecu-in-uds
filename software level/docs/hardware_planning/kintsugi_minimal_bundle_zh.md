# Kintsugi Minimal Bundle

这里说明的是 `hardware level/third_party/kintsugi_minimal/`。这是一套从旧 `kintsugi_artifact_zenodo` 复制出来的 `measurement-free` 最小组件集。

## 保留的内容

- `include/`
  `hp_manager / hp_guard / hp_applicator / hp_slot / hp_code / hp_def / hp_port / hp_exception / hp_freertos_mpu`
- `src/`
  对应的核心 `.c` 实现
- `ld/`
  `hp_layout_freertos.ld`
- `patches/`
  `FreeRTOS-Kernel.patch` 参考补丁
- `rtos_hooks/`
  `tasks.c` 的集成参考

## 当前主动做掉的事

- 没有复制 `hp_measure.h` 和 `hp_measure.c`
- 从复制进来的 `hp_manager.c`、`tasks.c`、`FreeRTOS-Kernel.patch` 里移除了对 `hp_measure.h` 的直接依赖

## 当前仍然保留的 measurement 宏分支

有些文件里还保留了类似：

- `HP_PERFORMANCE_MEASURE_*`
- `HP_MEASURE_FRAMEWORK`

这些是原始 Kintsugi 的条件编译分支。当前因为没有提供这些宏和头文件，它们默认处于关闭状态，不参与后续最小集成。

## 这套最小集的用途

- 先把 `manager / guard / applicator / slot / mpu / exception` 带进当前仓库
- 先支撑 `attack entry -> ECU -> hotpatch guard/apply` 这条主线
- 之后如果真要做性能实验，再单独把 measurement 子系统补回
