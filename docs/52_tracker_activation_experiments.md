# 2026-04-18 tracker 激活实验 — 基于 docs/51 真机 trace

## 输入

docs/51 交付 617 次真机 libtiny cmd trace,识别出 7 个 unidbg 从没调过的 cmd。按频次建议试 0x9657e61c (83 次,String "unknown")。

## 实施 diff (vs before)

### 删除 (真机首屏根本不调的 6 个)

| cmd (dec) | cmd (hex) | 旧名 |
|---|---|---|
| 2099694886 | 0x7d260ca6 | register_app |
| -1752783575 | 0x97864fa9 | ready signal |
| -378830707 | 0xe961e28d | getChannel |
| 378947270 | 0x1693ef06 | userGranted |
| -130547861 | 0xf83b432b | session id |

(cmd 1027279761 恢复了 — 单独删 init 失败,这个 cmd 可能 unidbg 场景特有的 SDK loader 用)

### 添加 (真机调过我们没调的)

| cmd (dec) | cmd (hex) | args | 真机频次 |
|---|---|---|---:|
| -223437958 | 0xf2ae9b7a | () | 2 |
| -835995473 | 0xce2bb8af | () | 1 |
| 954069261 | 0x38ddf10d | String("[]") | 1 |
| -1016326178 | 0xc36c17de | (String, String[]) | 3 |
| **-1772624356** | **0x9657e61c** | String("unknown") ×10 | 83 |

### 还没成功 (d7.a metric)

| cmd | 状态 |
|---|---|
| 1140071423 (d7.a) | UC_ERR_FETCH_UNMAPPED crash, 即便 args 完全对齐真机首次 (Long 2038853396, byte[30], byte[2]) |

d7.a 真机首屏 436 次,是最高频。内部可能读 Long arg 作为某个函数指针表的 key,表没在 unidbg 里 populate → 跳 unmapped → crash。需要先搞清楚哪个 init 把那个表填起来。

## 效果 (mua JSON)

**没突破** — JSON 还是 296B,`t` 字段仍然**缺失**:
```
{"a":"ECFAAF01","c":2,"k":"...","p":"a","s":"...","u":"...","v":"2.9.55"}
```

真机对照:
```
{"a":"ECFAAF01","c":2,"k":"...","p":"a","s":"...",
 "t":{"c":0,"d":0,"f":0,"s":4098,"t":0,"tt":[]},
 "u":"...","v":"2.9.55"}
```

但 **head4 变化了** (cb81461e → 238667e5 → fa8e1244 因 cmds 组合不同) — 证明新 cmd 影响了 libtiny state,只是没激活 tracker 这一特定模块。

## 实测 live server (baseline 保留)

| 端点 | proxy 上游 | client 收到 |
|---|---|---|
| flag_exp | 200 88KB | proxy/client 传输问题 (独立 bug) |
| config | 200 1.6MB | 同上 |
| device_type | upstream timeout | - |
| user_me | upstream timeout | - |
| verify_pag | upstream timeout | - |

**proxy 层面 2/5 accept 仍然保留**,没退化。3/5 failed 原因从 "直接 406" 变 "upstream timeout" (更 subtle) 和上一版 fake_rootfs 结果一致。

## 结论 / 下次突破口

0x9657e61c + 其他 3 个低成本 cmd 都调了,tracker 模块没激活。需要:

1. **d7.a 能跑通** — 真机首屏第一件事就是 d7.a,可能 tracker 的 state base 就来自前几次 d7.a 的 byte payload. UC_ERR_FETCH_UNMAPPED 要排查 libtiny 内部查表依赖。建议:
   - hook libtiny 代码入口看 Long→函数指针 表查找在 ARM 哪个地址
   - 看那个表在 libtiny 初始化时由谁写入
   - 或在 unidbg 里伪造该表的几个高频 entry

2. **0xafd151f7 cert chain** — 真机 13 次,传真实 Certificate List 可能效果更大。需要 mock `java.security.cert.X509Certificate`。

3. **换思路: tracker 可能不在 SDK 级初始化, 而是在 Application.onCreate 某段异步代码里由 Sentry/trace SDK 自己启动**。这种情况 unidbg 无法模拟,唯有硬编码 t 对象。

## Why / How to apply

**Why**: 黑盒大方向是"补环境让 native 自己 init"。加 0x9657e61c 等 cmd 是补 init 序列尝试。已证明能影响 state 但不足以激活 tracker 模块。

**How to apply**:
- 新 init cmd 试 1 轮: 单独跑 → 组合跑 → mua JSON decode 看有无 t 字段
- 有新真机 cmd 参数格式,先 UNIDBG_VERBOSE trace 看 JNI 调用是否正常完成再判断
- 维持 2/5 live server baseline 不能破坏
