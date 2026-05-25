# UDS Security Contract

这份文件是给 `hardware level` 的 C 实现用的，不引用 Python 代码，只复制它已经明确下来的规则。

## Session 状态

- `default session`
- `extended session`
- `seed issued`
- `unlocked`
- `locked out`

## 0x10 / 0x27 / 0x2E 主线规则

1. `0x10` 进入 `extended session`
2. `0x27 request seed`
   只有在 `extended session` 下允许
3. `0x27 send key`
   必须在 `seed issued` 之后
4. `0x2E DID write`
   只有在 `extended session` 且 `unlocked` 时允许

## Replay 规则

- 不能只做“重复 seq 打印”
- 至少要把 replay 变成“拒绝”
- 后续建议把 replay 计数或 nonce 与：
  - 当前 session
  - 当前 unlock 生命周期
  - 当前 DID 写上下文
  绑定

## Hotpatch 与诊断路径边界

- patch manager 可以先 `load / validate / schedule`
- 真正 `apply` 必须放在明确 safe point
- safe point 不能落在未完成的 security access 交换中间
- patch 激活后应清掉旧授权残留，避免旧 unlock 或旧 replay cache 穿透到新策略
