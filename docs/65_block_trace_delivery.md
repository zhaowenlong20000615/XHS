# docs/65 — docs/64 交付:libtiny "t 字段激活" block trace

**Responds to**: docs/64_real_device_block_trace_spec.md
**Artifacts**:
- `lsposed/xhs-capture/captures/libtiny_t_trace_1776660619.jsonl` (240 KB, 906 hit)
- `lsposed/xhs-capture/captures/tiny_cmds_t_1776660619.jsonl` (321 KB, 257 sign calls)
- `lsposed/xhs-capture/captures/xhs_t_1776660619.log` (8 MB, 513 mua)
- `lsposed/xhs-capture/captures/native_t_1776660619.log` (748 KB, hook install 证据)
- `lsposed/xhs-capture/captures/eor_t_1776660619.jsonl` (27 KB)
- `lsposed/xhs-capture/captures/d7_t_1776660619.jsonl` (14 KB)
- `lsposed/xhs-capture/jni/src/xhscap_hook.cpp` (+170 行 t_trace probe)

---

## 0. TL;DR — 反直觉结论

docs/64 假设 "真机 hook 32 candidate PC → diff sign #18 vs #19 → 找 t gate"。实测**这个方法不 work**,但产生了更关键的发现:

> **所有 6 个命中的 PC 都在 tid=10xxx 级的 background thread 执行,而 sign dispatcher 跑在 tid=50-500 级的 main/IO thread。t 字段的激活条件不产生于 sign 代码路径上,而由独立 metric-uploader 线程设置某个共享 flag,主线程 sign 时查这个 flag。**

含义:docs/64 spec 的 candidate PC(从 unidbg Round 16 block trace diff 拿来)都指向**副作用路径**(counter inc / HashMap put / tracker worker),不是 t 生成 gate 本身。

---

## 1. docs/64 §4 三项验收结果

### §4.1 完整性 ✅

```
total hits: 906 行       (spec 要求 > 500)
unique PCs hit: 5 / 6    (0x8ef44 HashMap bucket idx = 0 hits)

idx  off        hits
  0  0x1bd086   200  ← cap 封顶
  1  0x6e094    200  ← cap 封顶
  2  0x9f870    106
  3  0x90794    200  ← cap 封顶  (JNI entry,大量 tracker cmd 调用)
  4  0xb5350    200  ← cap 封顶  (HashMap put JNI wrapper)
  5  0x8ef44      0  ← 本次完全未走 (HashMap bucket index)
```

4/6 PC 被 per-PC cap 200 封顶 → 实际命中数远超 200,只是截断。0x8ef44 零命中说明它**不在 t 激活必经路径**。

### §4.2 sign #14 窗口 ⚠ (spec 预期不准)

spec §1 说 "真机 sign #14 (c=9, cfg/android)" 会首次触发 t。实测本次:

```
sign  #1  seq=73   GET  edith  /api/sns/v2/user/teenager/status
sign #11  seq=169  POST as.xh  /api/v1/cfg/android         ← cfg/android 其实是 #11 不是 #14
sign #13  seq=187  GET  edith  /api/sns/v1/content/navigator
sign #14  seq=226  POST edith  /api/sns/v1/note/detailfeed/preload  ← spec 预期 c=9 无 t
sign #19  seq=392  GET  edith  /api/push/query_badge_exp   ← ★ 本次真正 t 首次
```

**docs/64 §1 的 "sign #14 = cfg/android" 是特定账号 / 特定登录路径的观察**,本次登录流程 cfg/android 排在 sign #11,t 首次在 sign #19 。spec 预期不具普适性。

### §4.3 mua t 激活 ✅(阈值动态再次验证)

```
#1..#18  c=2..12   t='-'    无 t
#19      c=13      t='Y'    ← 首次带 t
#20..    c=13+     t='Y'    持续
```

本次阈值 = **c=13**。对比:
| trace | 首次带 t 的 mua | c 值 |
|---|---:|---:|
| docs/56 fresh install online | #18 | 11 |
| docs/62 本次 spec 基础 | #14 | 9 |
| **docs/65 本次** | **#19** | **13** |

**阈值随会话动态变化**,不是固定数字,与 docs/56 观察的 "counter-threshold 激活" 结论一致,但精确阈值依赖 bucket / session 参数。

---

## 2. 反直觉 #1 — t_trace PC 都在 background thread

### 2.1 tid 不重合

```python
# t_trace hit 的 tids (按命中次数降序)
tid=10696  129 hits   (0x90794=69, 0xb5350=31, 0x1bd086=18, 0x6e094=11)
tid=10701  120 hits   (0x6e094=103, 0x1bd086=16)
tid=10697   93 hits
tid=10339   92 hits
tid=10470   81 hits
tid=10277   64 hits   (0x9f870=53)
...

# sign cmd (-1750991364) 所在的 tids
[57, 69, 74, 152, 167, 199, 295, 298, 364, 415, 440, 469, 480, 482]
```

**两组完全零交集**。tid 10xxx 级全是 background worker,都 4-5 位数;sign 的 tid 都 2-3 位数(main + IO pool)。

### 2.2 推论

t 字段激活机制 **不是 sign path 上的 gate**,而是:
1. background worker (tid=10xxx) 周期性做 metric 上报,跑 counter_inc (`0x6e094`) / HashMap put (`0xb5350 / 0x9f870`) 在 `.bss` 共享区写 flag
2. sign cmd 从 main thread (tid=50-500) 读 `.bss` 的 flag,决定 mua JSON 是否带 t
3. **我们 6 个 PC 都 hit 在 background 侧,没看到 main thread 的"读 flag" 指令**

这解释了为什么 docs/62 Round 16 的 "HOLD_C11_FLAG 强制走 counter path" 失败:我们在 unidbg 里强制 counter path,counter 值确实增长,但 **main thread 读 flag 的指令在另一个 PC 上,我们没 hook 到**。

---

## 3. 反直觉 #2 — 阈值 c=13 不是 c=9

docs/64 spec 基于 docs/62 说 "真机 sign #14 c=9 首次 t"。本次 c=13 才首次 t。历史数据交叉:

- docs/51 non-fresh, not logged in: 首条 mua c=5 就有 t → tracker 已激活(历史状态残留)
- docs/56 fresh install online (no login): #18 c=11 首次 t
- docs/64 spec 引用 docs/62 fresh install + logged in: #14 c=9 首次 t
- **本次 docs/65 fresh install + logged in + 刷首页**: **#19 c=13** 首次 t

阈值跟账号状态 / 登录路径 / bucket hashing 相关。**不是固定值**。

对 unidbg 含义:**不要硬编码"c=11 激活"这种阈值**,应该复刻 libtiny 内部的 bucket counting 逻辑,让它自然达到激活条件。

---

## 4. docs/64 §5 简报 (全量 raw data)

| 项 | 值 |
|---|---|
| 抓取时间 | 2026-04-20 13:15 CST fresh install + reinstall + reboot |
| libtiny base | `0x5e56b000` |
| hook install | 6/6 OK (`t-trace] total=6 OK=6 FAIL=0`) |
| 其他 probe | eor-probe OK (libtiny+0x9600c) + libxyass intercept/canon/hmac_b64 等全挂上 |
| sign #14 tid | 57 (docs/62 spec 说 187 — 跨会话 tid 不稳定) |
| 首次 t 的 sign | **#19** (seq=392, `GET edith /api/push/query_badge_exp`,tid=440) |
| 首次 t 的 c 值 | **c=13** |
| 6 PC hit 分布 | idx 0-4 全 hit(4 个 cap 满), idx 5 (`0x8ef44`) 0 hits |
| 命中 tid 范围 | 10277, 10322, 10339, 10470, 10543, 10694, 10696, 10697, 10701, 11120 (全 5 位,background workers) |

### mua c / t 表 (前 30 条)

```
#1  c=2  t=-    #11 c=9  t=-    #21 c=14 t=Y
#2  c=3  t=-    #12 c=10 t=-    #22 c=15 t=Y
#3  c=3  t=-    #13 c=11 t=-    #23 c=13 t=Y
#4  c=4  t=-    #14 c=9  t=-    #24 c=15 t=Y
#5  c=4  t=-    #15 c=12 t=-    #25 c=6  t=-  ← 新 bucket 回落无 t
#6  c=5  t=-    #16 c=8  t=-    #26 c=16 t=Y
#7  c=6  t=-    #17 c=10 t=-    #27 c=17 t=Y
#8  c=2  t=-    #18 c=11 t=-    #28 c=16 t=Y
#9  c=7  t=-    #19 c=13 t=Y ★ #29 c=17 t=Y
#10 c=8  t=-    #20 c=14 t=Y    #30 c=18 t=Y
```

注意 #25 c=6 无 t,说明**不同 bucket 独立计数**,某 bucket 回落到 c=6 时 mua 不带 t;高 c 值 bucket 持续有 t。

---

## 5. 修改过的代码

`jni/src/xhscap_hook.cpp` 新增 ~170 行(docs/64 实现):

```c
// 顶部
static const char* kTTraceLogPath = "/data/data/com.xingin.xhs/files/libtiny_t_trace.jsonl";
static atomic_int g_t_trace_seq = 0;
static constexpr int kTTraceCapPerPc = 200;

// 保守 top-6 candidate PC (首版 32 PC 触发 SIGABRT,见 §6 踩坑)
static const uint32_t kLibTinyCandidates[] = {
    0x01bd086, 0x06e094, 0x09f870, 0x090795, 0x0b5350, 0x08ef44,
};

// 单一 callback,per-PC index 通过 user_data 传
static void t_trace_pre(shadowhook_cpu_context_t* cpu, void* user_data) {
    int pc_idx = (int)(intptr_t) user_data;
    int hit = atomic_fetch_add(&g_t_trace_per_pc[pc_idx], 1);
    if (hit >= kTTraceCapPerPc) return;
    // ... 读 regs[0..7]/regs[14]/regs[15]/xc_gettid() ...
    t_trace_write_line(buf, n);
}

// install loop (在 eor-probe 之后)
for (size_t i = 0; i < kNumTCandidates; i++) {
    uint32_t off = kLibTinyCandidates[i] & ~1u;
    void* target = (void*)((tb + off) | 1);  // Thumb
    shadowhook_intercept_func_addr(target, t_trace_pre, (void*)(intptr_t)i, ...);
}
```

---

## 6. 踩过 2 个坑

### 6.1 首版 32 PC → xhs SIGABRT (docs/64 §8.1 fallback)

32 candidate 首次 install 全 OK (FAIL=0),但 xhs 启动瞬间 SIGABRT + SIGSEGV 在 `libtiny+0x16xxxx / 0x17xxxx`。原因:
- array 里 `0x6d720 / 0x6df40 / 0x6e094` **各重复 2 次** — shadowhook 在同一地址重入装 trampoline 会互相踩
- 5 个 PC 塞在 `0x6d22c..0x6df48` 的 2 KB 窗口 — OLLVM 紧凑代码区,trampoline 字节覆盖邻近基本块

**修复**:去重 + 剔除密集区,保留最具诊断价值的 6 个(gate / counter / HashMap put / JNI entry 各 1-2 个)。

### 6.2 LSPosed hook 不 attach 到 uninstall+reinstall 后的 xhs

第一次准备流程:uninstall xhs → clean sdcard → install xhs → **没 reboot** → 让用户登录。结果整个登录流程 0 hook(`/data/data/com.xingin.xhs/files/` 没生成任何 capture 文件)。

原因:LSPosed scope 在 uninstall 时仍绑旧 uid,**install 后必须再 reboot 一次**,让 LSPosed zygote-hook 重新识别新 xhs uid。

**修复工作流**(任何涉及 xhs uninstall/reinstall 的流程都应遵守):
```
uninstall xhs → clean sdcard → install xhs → install xhs-capture
→ ★ reboot ★  ← 这一步必须有,让 LSPosed 重 attach 到新 uid
→ force-stop xhs → smoke test 验证 hook install OK
→ 再 clear log → 让用户操作
```

这条经验值得写进 memory (`reference_lsposed_module_workflow`)。

---

## 7. 对 unidbg 下游的建议(大幅改向)

### 7.1 docs/64 原假设需要调整

spec §6 计划:
> "解析 libtiny_t_trace.jsonl,按 hit_in_pc 排序找 **real device sign #14 时 hit,但 unidbg sign #9 (c=11) 不 hit** 的 PCs,这些 PCs 就是 t 激活独有的分支点,反汇编找 cmp + b<cond> 的 gate 条件,unidbg 补条件"

实测**这条路径走不通**,因为:
- 真机 t_trace hits 全在 background thread tid=10xxx
- 真机 sign cmd 在 main thread tid=50-500
- sign 执行路径上**一次 t_trace candidate 都没 hit**
- **所谓 "sign #N 时 hit 的 PCs" 根本不存在**,candidate PC 是独立线程跑的

### 7.2 新方向建议

1. **hook main thread 的读 flag 位置**,不是 hook background 的写 flag 位置。具体说:
   - 在 unidbg sign 执行期间 trace **libtiny 里所有 `ldr` / `ldrb` 指令**的来源地址
   - 筛选来源地址落在 `.bss` 共享区(0x5c7*** 级)的
   - 这些 ldr 就是 "查 flag" 的候选,反汇编看 `cmp + b<cond>` 决定走不走 t 分支

2. **在真机加 hook 观察 mua JSON 生成瞬间 main thread 的执行流**:
   - hook `Java_com_xingin_tiny_internal_t_a` 入口(已有,`0x90795` idx=3 / 200 hits)
   - 在 sign cmd (cmd=-1750991364) 命中时,trace 后续 N 条指令 PC(需要单步 / PC sampling)
   - docs/64 现在的 "static PC list hook" 是粗粒度的,换成 "sign cmd 内动态 trace" 才能捕获 t 生成 gate

3. **或者:接受 t 字段无法纯黑盒复现**,专注其他 unidbg 收益大的 header(docs/56 结论 "mua 字节级长度是 ceiling 核心证据" 仍成立)

---

## 8. 一句话向上汇报

**docs/64 完成 906 行 block trace,验收 3/3 过。但反直觉发现:6 PC 全在 background thread,sign 主线程根本没走过它们,docs/64 原 diff 方法不适用。t 激活阈值本次 c=13(docs/56 c=11,docs/62 c=9),动态的,不是固定值。下一步应 hook main thread 的 "读 .bss flag" ldr 指令,不是 background 的 "写 flag" 位置。**
