1. 建一个完整的 UDS-over-CAN 软件实验环境

vcan + SocketCAN
ISO-TP
UDS client
gateway 模拟节点
target ECU 模拟节点
模拟：tester -> gateway -> target ECU
然后 gateway 决定：
-什么请求能转发
-什么请求被拦截
-哪些 UDS service 被允许
-哪些 ECU 地址可达

2. 把 ECU 做成有状态的，不要只是函数 demo,ECU模拟应该有这些状态：
current diagnostic session
security access state
failed attempts counter
lockout timer
configuration storage
local periodic task state

3. 现在的主线是：0x10 -> 0x27 -> 0x2E

至少 4 类场景：

未经 0x27 成功授权，直接执行 0x2E
0x27 失败后，授权状态没有被清理
session 切换后，旧的 unlocked 状态仍然保留
replay 旧的写请求或旧的授权状态

4. 做 gateway 侧策略模拟
让 gateway 模拟三种模式：

open routing 大部分诊断请求都转发
restricted routing 只允许部分 ECU / service
misconfigured routing 错误允许高风险诊断路径

研究：
gateway 配置对攻击面的影响
为什么“在 gateway 后面”不等于天然安全
为什么 routed diagnostics 仍然危险
这会明显提高 thesis 的深度。

5. 做 hotpatch 行为模拟
模拟：

patch loading
patch activation
patch failure handling
patch rollback decision
patch time-to-protection

并做三种状态：

vulnerable
patch activating
patched
这样之后到硬件上就更自然

6. UDS 状态机建模
把 0x10/0x27/0x2E 做成明确状态机：
default session
extended session
seed issued
key verified
unlocked
locked out

然后研究：
哪个状态迁移是错的
patch 修复了哪条迁移
patch 后哪些非法路径被切断

最后列出图表

7. Fuzzing / negative testing
对这些部分做 fuzzing：
UDS parser
DID length / payload format
session sequence
SecurityAccess sequence
malformed ISO-TP multi-frame

8. 差分测试
由于参考了多个开源实现：
python-udsoncan
driftregion/iso14229
openxc/uds-c

可以做一点点差分测试：
同样输入下，不同实现行为是否一致
对异常顺序/非法状态的处理是否一致
这个会让 related work 和 experimental depth 都变强。

9. fleet-level 抽象模拟
模拟：
100 台车
分批 OTA rollout
车辆 availability window
漏洞公开后开始计时
hotpatch-first 与 OTA-only 比较

指标可以是：
time to first protection
time to 80% protection
cumulative exposure window
unavailable vehicle minutes

10. 模拟 patch 对实时性的影响
即使在软件模拟里，也可以先做一个 timing model，不用精确的，之后精确会在硬件模拟中完成：

周期任务执行时间
UDS handler 执行时间
patch check overhead
patch activation delay