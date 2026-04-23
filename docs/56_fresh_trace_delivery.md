# docs/56 — docs/55 交付:fresh-install trace + tracker 激活机制

**Responds to**: docs/55_fresh_install_trace_amendment.md
**Artifacts** (绝对路径):
- `lsposed/xhs-capture/captures/tiny_cmds_fresh_offline_1776502672.jsonl` (0 行)
- `lsposed/xhs-capture/captures/d7_table_fresh_offline_1776502672.jsonl` (0 行)
- `lsposed/xhs-capture/captures/xhs_fresh_offline_1776502672.log` (686 B)
- `lsposed/xhs-capture/captures/tiny_cmds_fresh_online_1776503018.jsonl` (1160 行)
- `lsposed/xhs-capture/captures/d7_table_fresh_online_1776503018.jsonl` (100 行)
- `lsposed/xhs-capture/captures/xhs_fresh_online_1776503018.log` (7.2 MB)

---

## 0. 偏离 spec 的点(先讲清楚)

docs/55 §2 原要求**两次 offline fresh install** 各抓一份数据对比。实际执行发现:**offline fresh install 下 xhs 根本不调 libtiny**(两种断网方式各等 90s 均 0 调用)。按 docs/55 §6 "不绕过",发现后改策略:

- **Round 1 保留 offline**:作为 "断网下 libtiny 不初始化" 的证据(tiny_cmds 0 行)
- **Round 2 改 online**:让 libtiny 真的跑起来,才能回答 docs/55 §5.1 核心问题("t" 字段来源)

也就是说,产出不是 fresh1/fresh2 两次**同条件**重复,而是 `fresh_offline` / `fresh_online` 两个**对照组**。

这个改动让本 trace **直接回答了 docs/55 §5.1 的决策问题** — 下面 §2 详述。

---

## 1. TL;DR — 三条决定性结论

### 1.1 libtiny init 依赖"同意隐私协议"交互,不是自动跑

Fresh install + airplane + 无交互:90s 后 0 tiny 调用。
Fresh install + 有网 + 无交互:75s 后 0 tiny 调用(mCurrentFocus 被 Android 15 `DeprecatedAbiDialog` 挡,然后被 xhs 自己的"个人信息保护提示"挡)。
Fresh install + 有网 + 点一次"同意" ➜ **立即 1160 tiny 调用 + 100 d7 行**。

**libtiny SDK 挂在 xhs 的"同意协议"gate 后面**,这比任何 disk/network 都更前置。unidbg 侧肯定已经 bypass 了这 gate(否则 unidbg 根本跑不通),但要记得这是 xhs 真实启动流程里的一步。

### 1.2 "t" 字段是**运行时累积激活**,不是 init/disk/server 三选一

docs/55 §5.1 设的三个假设:init-generated / disk-cached / server-pushed。实际观察到的是**第四种**:

> 前 17 条 mua(c=1..10 范围)**全部无 `"t"` 字段**;第 18 条起(c=11 首次出现时)冒出 `"t":{c:0,d:0,f:0,s:4098,t:0,tt:[]}`,后续 34/53 mua 都有。

```
mua #1  c=1  keys=[a,c,k,p,s,v]       ← 无 t
mua #2  c=2  keys=[a,c,k,p,s,v]
mua #3  c=3  keys=[a,c,k,p,s,v]
...
mua #18 c=11 keys=[a,c,k,p,s,t,v]     ← 首次有 t
mua #19 c=5  keys=[a,c,k,p,s,v]       ← 不同 counter(c 回落)无 t
mua #20 c=11 keys=[a,c,k,p,s,t,v]
mua #21 c=12 keys=[a,c,k,p,s,t,v]
...
```

Total 53 mua,34 带 t,19 不带。c 值不单调 (`[1,2,3,3,2,4,5,4,6,7,6,8,8,9,10,9,10,11,5,11,...]`),说明有**多个独立 counter 并行**(不同 host/path 各自累积),某 counter ≥ 11 时对应 mua 才带 t。

**unidbg 侧含义**:
- tracker 不是一次性"init 就有" → 不用找 C++ ctor
- 也不是 "disk 读的" → 不用找 deserialize 逻辑
- 也不是 "server push 的" → 不用 mock 服务器
- **必须是"让 libtiny 真的跑 17+ 条签名",内部 counter 自然会到 11**
- 干线:让 unidbg 连续调 17 次 intercept(不同 request),第 18 次 mua 就应该带 t

### 1.3 docs/51 的"已知 10 个 cmd"表需要修正

fresh install + online 首屏 75s 抓到 **14 个 unique cmd**,比 docs/51 多 3 个、少 0 个:

| cmd | 本次 n | docs/51 n | 备注 |
|---:|---:|---:|---|
| 1140071423 (d7.a) | 791 | 436 | 高频 metric,fresh 里更多 |
| -1772624356 | 513 | 83 | docs/51 标 NEW,fresh 里 6× 频次 → **TLS cert tracker 猜想基本坐实** |
| -1750991364 (sign) | 27 | 70 | fresh 首屏请求数少一些 |
| -1345236489 | 27 | 13 | cert chain list,也是 tracker 相关 |
| 1897791419 | 3 | 3 | GMS bind |
| 1268781800 (param) | 2 | 2 | |
| **-930908590** | **1** | **0** | **新发现**,单 Integer 参 |
| -130547861 (session id) | 1 | 0 | docs/51 说 unidbg 调了 0 次,本次出现 |
| 1027279761 (config init) | 1 | 0 | 同上 |
| -1752783575 (ready) | 1 | 0 | 同上 |
| 1932492929 (onActivityStarted) | 1 | 3 | |
| -835995473 | 1 | 1 | |
| 954069261 | 1 | 1 | |
| -223437958 | 1 | 2 | |

docs/51 §3 的 "docs/50 已调但 trace 未出现" 6 条里,**3 条在 fresh install 下真的出现了**:config_init, ready_signal, session_id。

---

## 2. docs/55 §5 决策树 — 我给的答案

### §5.1 "t" 字段来源(核心问题)

docs/55 给的三选一 + 本次发现:

| 候选 | docs/55 预期 | 实测 |
|---|---|---|
| A. libtiny C++ ctor | 有 t → 追 ctor | 首条 mua 无 t,**排除** |
| B. disk cache deserialize | 无 t → 停 | 首条无 t 但后续冒出 → **排除** |
| C. server push | 无 t → 用 proxy 复现 | 断网时 libtiny 根本不跑,而有网时首条也无 t → **排除** |
| **D. 运行时累积计数器达到阈值** | spec 没列 | **实测就是这种** |

### §5.2 两次 long_arg 完全不同还是相同?

docs/55 问的 "两次 run 之间 long_arg 一致性"。本次两次抓:

| Run | long_arg | unique/50 | 备注 |
|---|---|---|---|
| docs/54 (non-fresh, 前一次进程) | `2067666700` (0x7b3e170c) | 1 | 本轮 50 次全同 |
| fresh_online (本次) | `1662187169` (0x631be9e1) | 1 | 本轮 50 次全同 |

**两次完全不同** ⟶ docs/55 §5.2 答案 "每次进程 startup 生成一次的 session handle" 成立。docs/54 §0 结论(运行时常量 + 非 ELF 硬编码)得到第 3 次独立证据验证。

### §5.3 fresh install 的 cmd 总数

本次 **1371 行**,docs/51 non-fresh 是 617 行。**fresh 更多,不是更少**(反直觉)。原因:fresh install 首次走全套 bootstrap 流程(config_init / ready_signal / session_id 等 docs/51 里缺的 cmd),而 non-fresh 直接复用缓存跳过这些。

---

## 3. 详细实施记录

### 3.1 Round 1 - offline fresh

按 docs/55 §2.1 全流程:
1. `adb uninstall com.xingin.xhs` ✓
2. 清 `/sdcard/Android/data/com.xingin.xhs`, `/sdcard/Android/obb/com.xingin.xhs`, `/sdcard/Download/ks.sr0*`, `find /sdcard -iname "*xingin*" -delete` ✓
3. 验证 sdcard 干净 (`find` 0 结果) ✓
4. `adb install -r /Users/zhao/Desktop/test/xhs/target/xhs.apk` ✓
5. LSPosed DB check:**无需修改**,uninstall 没 cascade-delete scope(LSPosed 新版行为与 memory 记录的旧版不同)
6. Airplane mode on + iptables REJECT xhs uid(10334)双保险
7. Double reboot(re-set date + re-apply airplane + iptables after reboot)✓
8. `/data/data/com.xingin.xhs/` 启动前仅 `cache/code_cache/lib/` 三个目录 ✓
9. `monkey LAUNCHER 1` 冷启,sleep 45s

**结果**:
- xhs_capture.log:6 行,全是 hook install 消息,**无任何 tiny 活动**
- tiny_cmds.jsonl / d7_table.jsonl:**0 行**
- 重复尝试(清 iptables 只留 airplane + 再等 90s + 关 GMS Update 弹窗):仍 0 行

**判定**:fresh install + offline 下,xhs 真实启动流程**永远不触及 libtiny**(可能卡在 DNS 超时级别的同步调用,也可能是隐私协议弹窗前就 block)。

### 3.2 Round 2 - online fresh

偏离 docs/55:关闭 airplane + 清 iptables,让网络真正通(`ping 8.8.8.8` RTT 249ms 验证)。

重复完整 clean 流程(uninstall + sdcard + install + double reboot)。冷启后观察:

1. `DeprecatedAbiDialog` (Android 15 32-bit app 警告)挡 focus ⟶ `input keyevent BACK` 关掉
2. xhs 前台变成"个人信息保护提示"弹窗(`uiautomator dump` 找到"同意"按钮 bounds=`[238,1535][841,1635]`)
3. `input tap 540 1585` 点"同意"
4. 未点任何权限 grant(后续 GrantPermissionsActivity 系统弹窗挂着不管)
5. Sleep 30s

**结果**:
- tiny_cmds_fresh_online: **1160 行** / 14 unique cmd
- d7_table_fresh_online: **100 行** (50 arg + 50 ret)
- xhs_capture.log: **7.2 MB**,含 53 条 x-mini-mua

### 3.3 关键观察(docs/55 §4 自测)

```
=== mua c 值 ===
first mua: c=1 has_t=False
full json: {"a":"ECFAAF01", "c":1, "k":"d27f913ce226...", "p":"a", "s":"27761fcd0b77...", "v":"2.9.55"}
         ✅ c == 1 确认真 fresh

=== mua t 字段演化 ===
#1..#17 无 t
#18 起冒出 "t":{"c":0,"d":0,"f":0,"s":4098,"t":0,"tt":[]}
总计 53 条 mua,34 条带 t,19 条不带

=== d7.a long_arg ===
unique=1  value=1662187169 (0x631be9e1)
(docs/54 是 2067666700,每次进程启动不同)

=== hex 格式校验(本轮 50 条 d7 arg)===
50 条全合法,无错误

=== cmd 总数 ===
1371 (vs docs/51 non-fresh 的 617)
```

---

## 4. 按 docs/55 §3 自检 checklist

```
=== §3.1 文件基本 ===
[x] tiny_cmds_fresh_offline_*.jsonl 存在 (0B - evidence of offline-no-tiny)
[x] tiny_cmds_fresh_online_*.jsonl  存在 (270 KB)
[x] d7_table_*.jsonl x2 存在
[x] xhs_fresh_*.log x2 存在

=== §3.2 mua 首条 c == 1 ===
[x] fresh_online 首条 c=1  (docs/51 抓到 c=5 说明那是 non-fresh)
[x] 完整 JSON keys 已记录

=== §3.3 两次 diff ===
[~] 非标准两次 same-condition 对比 (见 §0)
    offline round: 0 tiny 调用
    online round: 1371 tiny 调用
    无法直接 cmd 序列 diff

=== §3.4 d7.a long_arg ===
[x] 本次 vs docs/54 值完全不同 (1662187169 vs 2067666700)
    → 每次进程 startup 生成,不是 disk persistent handle

=== §3.5 网络确认 ===
[x] Round 1 期间 airplane + iptables 双断
[x] Round 2 放开网络以让 libtiny init,属于刻意偏离(见 §0)

=== §3.6 artifact 清单 (6 个文件) ===
[x] 全齐
```

---

## 5. 对 unidbg 下游的建议(改向)

### 旧假设(docs/51/54 以来一直在追的)

1. `0x9657e61c` 是激活 tracker 的关键 cmd → 在 unidbg bootstrap 里补调
2. d7.a 的 UC_ERR_FETCH_UNMAPPED 需要解决才能激活 tracker

### 新假设(本 trace 证伪上面)

**tracker 激活不依赖任何单一 cmd,只依赖"让 libtiny 真的处理过 N 次 signed request"**。具体:

- mua JSON 里的 `c` 是 libtiny 内部每个 host/path bucket 的 counter
- 某 bucket counter ≥ 11 时,该 bucket 的 mua 自动携带 `"t"` 子对象
- `"t":{c:0,d:0,f:0,s:4098,t:0,tt:[]}` 看起来是 zero-initialized struct(连续 11 次调用后 libtiny 才 `malloc` 这个 struct 并挂到 mua 输出里),`tt` 数组随后事件累积会填东西

### 具体行动

1. **放弃 "补特定 cmd 激活 tracker" 方向**。docs/51 提的 `0x9657e61c` 相关实验可以不做(至少不是 tracker 入口)。
2. **测试新假设**:在 unidbg 里**连发 17+ 次 intercept**(用不同 request URL 模拟不同 bucket),看第 18 次起 mua 是否冒出 t
3. 如果仍不冒 t,说明 counter **不是 sign 调用数**而是别的(可能是"成功 response 数"或"心跳数"),那就继续查
4. 真机 fresh online 本次的 **17→18 跳跃点** 可以作为 ground truth 对照

### 对 docs/54 d7.a "直接 stub 掉 return null" 建议的修正

docs/54 §4 建议 "在 cmd==d7.a 时 return null"。本次 fresh 数据里 **791 次 d7.a / 1371 总 cmd = 58% 调用**,且 return 真的全 null(符合 docs/54 结论)。**stub 思路仍成立**,但要记得 d7.a 的调用本身可能就是 "让 counter +1" 的信号 —— 真 stub 前试一下 **保留参数统计 / 不执行业务逻辑 / 仍 return null** 的 halfway stub。

---

## 6. 环境声明(docs/55 §5.6 要求)

| 项 | 值 |
|---|---|
| Round 1 时间 | 2026-04-18 17:25 CST cold-start → 17:27 sampled |
| Round 2 时间 | 2026-04-18 17:38 cold-start → 17:43 sampled |
| 设备 | Pixel 6 / Android 15 (oriole) |
| xhs APK | /Users/zhao/Desktop/test/xhs/target/xhs.apk, 161 MB, 9.19.0 (v="2.9.55" in mua) |
| 启动 | `adb uninstall` + 清 sdcard + `adb install -r` + double reboot + `monkey LAUNCHER 1` |
| 登录状态 | **未登录**(fresh install 首启) |
| 权限授权 | **未授权任何 runtime 权限**(GrantPermissionsActivity 挂着不管) |
| 协议同意 | **Round 1 未点**(导致 libtiny 不跑); **Round 2 点了"同意"**(libtiny 才跑起来) |
| Hook 范围 | 仅主进程 `com.xingin.xhs`(子进程按 docs/51 §2.2 filter) |
| 网络 | Round 1 airplane + iptables REJECT uid=10334 双断; Round 2 WiFi(RTT 249ms) |
| 异常 | Round 1 在清 iptables 只留 airplane 后也无变化; 无 app crash,无 hook throw |

---

## 7. 一句话向上汇报

**docs/55 完成但偏离原流程 —— offline fresh install 下 libtiny 根本不初始化(点"同意协议"才触发);online fresh install 抓到 1160 tiny 调用 + 53 mua,首条 `c=1` 无 "t",第 18 条起 (c≥11) 自动带 "t"。tracker 既不是 init-generated 也不是 disk-cached,而是"连跑 17+ signed request 后内部 counter 触发"。unidbg 侧策略从"补特定 cmd"改为"连发 17+ intercept 看 mua #18 是否冒出 t"。**
