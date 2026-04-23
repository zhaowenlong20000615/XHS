# 需求: 真机 shadowhook 抓 libtiny main thread 在 sign 内读 `.bss` flag 的 ldr/ldrb 指令

**受众**: LSPosed + shadowhook 窗口 (`lsposed/xhs-capture/jni/`)
**工具**: **shadowhook 不要 Frida** — Frida 在 Pixel 6 / Android 15 已验证死路
**产出**: 5 个 capture 文件 + 1 份简报(见 §9/§10)
**预期工时**: 3-4 小时
**你的任务**: 按此 spec 跑真机实验并交付数据。不需要做 unidbg 侧任何事 — 那是我这边的活。

---

## §0 你要做的 5 件事(TASK CHECKLIST)

| # | 任务 | 产出 | 预计 |
|---|------|------|------|
| T1 | 跑 §4 的 scan Python 脚本生成 `bss_ldrb_candidates.json` | 最多 60 个 PC | 15 分钟 |
| T2 | 把 scan 输出的 C 数组贴进 `xhscap_hook.cpp` 的 §5 标记位置 + 新增回调 | 改 `xhscap_hook.cpp` ~80 行 | 30 分钟 |
| T3 | `cd lsposed/xhs-capture && ./build.sh` 编译 APK | `build/xhs-capture.apk` | 5 分钟 |
| T4 | 按 §7 跑真机(clean + reboot + **smoke test** + 登录 + 刷 60s + pull) | 5 个 capture 文件 | 90 分钟 |
| T5 | 按 §8 跑 Python diff,按 §10 格式贴简报 | 简报 7 条 | 30 分钟 |

读完 §1 两条 Pitfall 和 §2 smoke test 协议之后再开始 T1。
**本 spec 自足 — 不需要读 docs/60-65 历史文档**。

---

## ⚠️ §1 两条 MUST READ Pitfall(前置读,否则白干)

### Pitfall P1 — uninstall + install xhs 后 **必须 reboot**

LSPosed scope 绑 xhs **旧 uid**。uninstall+install 后 xhs 拿新 uid,LSPosed zygote-hook 不认 → **所有 hook 静默失效**,`/data/data/com.xingin.xhs/files/` 下 0 文件。你会以为"代码没跑起来",实际是 hook 没 attach。

> **memory 出处**: `reference_lsposed_uninstall_reboot_gotcha`
> **血泪例**: docs/65 首次尝试因漏此步骤,用户登录 + 3 分钟操作白干,pull 0 文件。

**正确流程**:`adb install xhs.apk → adb install xhs-capture.apk → adb reboot → 等 boot → smoke test`。

### Pitfall P2 — shadowhook inline hook 对 OLLVM 密集区互相踩

- 32 PC 同时装,**一个 2 KB 区域放 5 个** → 启动瞬间 SIGABRT/SIGSEGV
- 原因:每个 hook 写 ~4 字节 BKPT + relocate 附近几条指令,相邻 hook 覆盖彼此的 prologue

**规则**:
- 一批最多装 **≤ 12 个** PC
- 任意两个 PC 间距 **≥ 32 字节**(一个 trampoline 的实际占用)
- **不要重复 PC**(数组里别同一个地址写两次)
- 集中在 OLLVM 已知密集区(`lib+0x6d***..0x6f***`、`lib+0x16****..0x17****`)要额外谨慎

> **memory 出处**: `project_t_field_background_thread` §2.1
> **血泪例**: docs/65 首版 32 PC 里 `0x6d720/0x6df40/0x6e094` 重复装 + 5 PC 在 2KB 内,xhs 立刻崩。简化到 top-6 + 去重才稳。

---

## §2 Smoke Test 协议(每次 reboot 后强制,判死活 5 秒)

先让 xhs 跑 8 秒,验证 hook attach 到了。hook 没上 **绝对不要让用户登录**(浪费用户时间,docs/65 已验证)。

```bash
# clean log → 启 xhs 8s → 检查
adb shell "am force-stop com.xingin.xhs"
adb shell "su -c 'rm -f /data/data/com.xingin.xhs/files/*.jsonl /data/data/com.xingin.xhs/files/*.log 2>/dev/null'"
adb shell "monkey -p com.xingin.xhs 1"
sleep 8

# 必须全部看到(非空)
adb shell "su -c 'ls -la /data/data/com.xingin.xhs/files/ | grep -E \"(bss_ldrb_trace|xhs_native_trace|xhs_capture).+[^0]\"'"
adb shell "su -c 'grep bss-ldrb /data/data/com.xingin.xhs/files/xhs_native_trace.log | head'"
```

**判定**:
- 看到 `[bss-ldrb] INSTALL OK` 条目 ≥ 40 行 → ✅ 进 §7 让用户登录
- 0 行 / 文件不存在 → ❌ **回 §7.1 再 reboot 一次**,不要跳过

---

## §3 背景 — 为什么要 hook main thread 的 `.bss` 读(docs/65 反证)

docs/65 在 libtiny 6 个 candidate PC 装 shadowhook,抓 906 hits。实测:

| 维度 | 观察 |
|---|---|
| 6 PC 命中的 **tid** | 10277, 10339, 10470, 10694, 10696, 10697, 10701, 11120(全 5 位,background worker) |
| sign cmd (-1750991364) 的 **tid** | 57, 69, 74, 152, 167, 199, 295, 440, 469, 480, 482(全 2-3 位 main/IO) |
| 两组交集 | **0** |

**结论**: libtiny 的 `"t":{...}` 字段激活 **不是 sign 执行路径上的 if 分支**,而是:

```
     background worker (tid=10xxx)
         |
         v
     写 .bss flag @ lib+0x5c7***
         |
         v
     main thread sign cmd (tid=50-500)
         |
         v
     ★ ldrb rX, [rY+imm]  从 .bss 读 flag ★   ← 这里就是 t gate
         |
         v
     cmp + b<cond> → 决定 mua JSON 是否带 "t"
```

docs/65 hook 的 6 PC 全在**写侧**(background 写 flag),docs/66 要找**读侧**(main 读 flag)。

**已知相关 `.bss` 区**:
- `lib+0x5c7ac6 / 0x5c7ac8` — docs/62 Round 16 找到的 byte_flag(counter path 相关,**不一定是 t 的**,要实测)
- `lib+0x5c41d8` — docs/60 EOR mask 源(不同机制,优先级低)
- 整个 `lib+0x5c0000..0x5cffff` 是 libtiny 运行时共享状态区

---

## §4 T1 — 静态反汇编生成 candidate PC

用 capstone 扫 libtiny.so,找所有读 `.bss [0x5c0000, 0x5d0000)` 的指令。

### §4.1 拉真机 libtiny.so

```bash
adb shell 'pgrep -f com.xingin.xhs | head -1' | xargs -I{} adb shell "cat /proc/{}/maps" | grep libtiny | head -1
# 用上面输出的路径:
adb pull <path> /tmp/libtiny.so
```

### §4.2 Python scan 脚本(全量,直接可跑)

```python
#!/usr/bin/env python3
"""Scan libtiny.so for all ldr/ldrb/ldrh instructions whose literal pool
references a .bss address in the target range. Emits C array for xhscap_hook.cpp."""
import json, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ELF = '/tmp/libtiny.so'
TARGET_LO = 0x5c0000
TARGET_HI = 0x5d0000
# 根据 readelf -S libtiny.so 获取 .text 范围; 保守值:
TEXT_LO = 0x1000
TEXT_HI = 0x5b0000

data = open(ELF, 'rb').read()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True

# pass 1: 找所有 literal 指向 0x5c**** 的 file offset
literal_hits = {}  # file_off -> literal_value
for i in range(TEXT_LO, min(TEXT_HI, len(data)) - 4, 4):
    v = int.from_bytes(data[i:i+4], 'little')
    if TARGET_LO <= v < TARGET_HI:
        literal_hits[i] = v

print(f"[pass1] literal pool entries pointing to .bss: {len(literal_hits)}")

# pass 2: 反向找引用这些 literal 的 ldr 指令
# Thumb2 "ldr rX, [pc, #N]" 的 N 是 PC-relative,PC 是指令对齐后的下一指令 = (addr+4) & ~3
# 所以 literal @ L 被 ldr @ P 引用,当且仅当 (P+4) & ~3 + N == L, N 是 10-bit imm * 4
candidates = []  # list of (pc, insn_bytes, disasm, literal_val)
for off in range(TEXT_LO, min(TEXT_HI, len(data)) - 4):
    # ARM Thumb 指令 2 或 4 字节,简化全 4B 尝试
    for insn in md.disasm(data[off:off+4], off, count=1):
        mnem = insn.mnemonic
        if mnem not in ('ldr', 'ldrb', 'ldrh'): continue
        op = insn.op_str
        if '[pc' not in op: continue
        # 解析 "ldr rX, [pc, #N]"
        try:
            n_str = op.split('#')[-1].rstrip(']')
            n = int(n_str, 0)
        except: continue
        lit_addr = ((insn.address + 4) & ~3) + n
        if lit_addr not in literal_hits: continue
        candidates.append({
            'pc': insn.address,
            'bytes': insn.bytes.hex(),
            'disasm': f'{mnem} {op}',
            'literal_addr': lit_addr,
            'literal_val': literal_hits[lit_addr],
            'bss_rel': literal_hits[lit_addr],
        })
        break

print(f"[pass2] ldr/ldrb/ldrh → .bss literal references: {len(candidates)}")

# pass 3: 去重 + 间距过滤(Pitfall P2)
# 按 PC 排序,同一个 PC 只保留一次;相邻 PC 间距 < 32B 的丢弃后一个
candidates.sort(key=lambda c: c['pc'])
filtered = []
last_pc = -1000
for c in candidates:
    if c['pc'] == last_pc: continue
    if c['pc'] - last_pc < 32:
        # 太近 skip
        continue
    filtered.append(c)
    last_pc = c['pc']
# 再限 60 个防爆炸
filtered = filtered[:60]
print(f"[pass3] after dedup + spacing ≥32B + cap 60: {len(filtered)}")

# 输出 JSON + C array
with open('bss_ldrb_candidates.json', 'w') as f:
    json.dump(filtered, f, indent=2)

print("\n// ========== paste into xhscap_hook.cpp §5.1 ==========")
print("static const uint32_t kBssLdrbCandidates[] = {")
for c in filtered:
    print(f"    0x{c['pc']:06x},  // {c['disasm']}  → .bss+0x{c['bss_rel']-0x5c0000+0x5c0000:x}")
print("};")
print(f"static constexpr size_t kNumBssLdrbCandidates = sizeof(kBssLdrbCandidates)/sizeof(uint32_t);  // = {len(filtered)}")
```

### §4.3 验收 T1

- [ ] `bss_ldrb_candidates.json` 生成,数组长度 **10 ≤ n ≤ 60**
- [ ] 相邻 PC 间距 ≥ 32 字节(Pitfall P2)
- [ ] 没有重复(脚本已去重但自查一下)
- [ ] 脚本输出的 C 数组贴到下游输出(准备给 T2 用)

**若 < 10 个候选**:扩大扫描范围,把 `TARGET_HI = 0x5e0000`(加 64 KB);或扫 `.data` 段(PT_LOAD 里 WR 段)。
**若 > 60 个候选**:改 `filtered = filtered[:60]` 为 `[:40]`,T2 分两批装(第一批先 20 个试,smoke 过再加)。

---

## §5 T2 — 把 probe 代码贴进 `xhscap_hook.cpp`

### §5.1 找插入点

在 `jni/src/xhscap_hook.cpp` 现有 `libtiny_eor_pre` 定义**之后**、`// ---------- lightweight JSON-ish line writer` **之前**插入:

```c
// ============================================================================
// docs/66 — libtiny main thread .bss 0x5c**** ldr/ldrb probe
//
// Hook all ldr/ldrb/ldrh instructions (sourced from static disassembly, see
// bss_ldrb_candidates.json) that read from the .bss 0x5c**** region. At each
// hit, log {pc, lr, loaded_val, r0..r3, tid}. Filter hits by tid learned
// from Java_com_xingin_tiny_internal_t_a (0x90795) when cmd=-1750991364
// (the sign dispatcher) — only those hits belong to the sign path that
// actually reads the t-gate flag.
// ============================================================================

static const char* kBssLdrbLogPath =
    "/data/data/com.xingin.xhs/files/bss_ldrb_trace.jsonl";
static atomic_int g_bss_ldrb_seq = 0;
static constexpr int kBssLdrbCapPerPc = 500;

// ===== PASTE from §4.2 scan output START =====
static const uint32_t kBssLdrbCandidates[] = {
    // TODO T2: replace this block with scan output
    0xDEADC0DE,  // placeholder
};
static constexpr size_t kNumBssLdrbCandidates =
    sizeof(kBssLdrbCandidates) / sizeof(uint32_t);
// ===== PASTE END =====

static atomic_int g_bss_ldrb_per_pc[128];  // cap >= kNumBssLdrbCandidates

// sign main tid 白名单 — 由 tiny_dispatch_pre 动态维护
static std::set<int> g_sign_tids;
static pthread_mutex_t g_sign_tids_mu = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t g_bss_ldrb_log_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_bss_ldrb_log_fd = -1;

static void ensure_bss_ldrb_log_open() {
    pthread_mutex_lock(&g_bss_ldrb_log_mu);
    if (g_bss_ldrb_log_fd < 0) {
        g_bss_ldrb_log_fd = open(kBssLdrbLogPath,
            O_CREAT | O_WRONLY | O_TRUNC | O_APPEND, 0666);
    }
    pthread_mutex_unlock(&g_bss_ldrb_log_mu);
}

static void bss_ldrb_write(const char* buf, size_t n) {
    pthread_mutex_lock(&g_bss_ldrb_log_mu);
    if (g_bss_ldrb_log_fd >= 0) { ssize_t w = write(g_bss_ldrb_log_fd, buf, n); (void) w; }
    pthread_mutex_unlock(&g_bss_ldrb_log_mu);
}

// 在 Java_com_xingin_tiny_internal_t_a 入口学习 sign tid
// 注意: r2 在 ARM JNI ABI 是第 2 个 Java 参 (cmd int), r3 是第 3 个 (jobjectArray args)
static void tiny_dispatch_pre(shadowhook_cpu_context_t* cpu, void* /*user_data*/) {
    int cmd = (int32_t) cpu->regs[2];
    if (cmd != -1750991364) return;  // 只关心 sign cmd
    int tid = (int) xc_gettid();
    pthread_mutex_lock(&g_sign_tids_mu);
    g_sign_tids.insert(tid);
    pthread_mutex_unlock(&g_sign_tids_mu);
}

static bool is_sign_tid(int tid) {
    pthread_mutex_lock(&g_sign_tids_mu);
    bool r = g_sign_tids.count(tid) > 0;
    pthread_mutex_unlock(&g_sign_tids_mu);
    return r;
}

static void bss_ldrb_pre(shadowhook_cpu_context_t* cpu, void* user_data) {
    int pc_idx = (int)(intptr_t) user_data;
    if (pc_idx < 0 || (size_t) pc_idx >= kNumBssLdrbCandidates) return;
    int hit = atomic_fetch_add(&g_bss_ldrb_per_pc[pc_idx], 1);
    if (hit >= kBssLdrbCapPerPc) return;

    int tid = (int) xc_gettid();
    // 在 sign tid 被学习出来之前也记录,下游 python 能基于后学习到的 tid 过滤
    // 但为了控制 log 量,前 1000 条全收,之后只收 sign tid 命中
    int seq = atomic_fetch_add(&g_bss_ldrb_seq, 1);
    if (seq > 1000 && !is_sign_tid(tid)) return;

    uint32_t pc = cpu->regs[15];
    uint32_t lr = cpu->regs[14];
    uint32_t r0 = cpu->regs[0], r1 = cpu->regs[1];
    uint32_t r2 = cpu->regs[2], r3 = cpu->regs[3];

    // 从 PC literal pool 读真实 .bss 地址
    // 注意: shadowhook hook 时 PC 可能是 trampoline 的地址, 而不是原指令 PC.
    // 实际 hook 模式下 cpu->regs[15] 是 shadowhook 替我们 adjust 过的,应该 = 原指令 PC
    // 但为保险,不信 PC,直接用 pc_idx 查静态表里记录的 literal_val (需要在 T2
    // 代码里把 scan 时拿到的 literal_val 也传下来).
    // 简化方案: 把 literal 值再算一次 from (PC&~3)+4+imm, 这里 imm 需要从原指令
    // 解码,太复杂. 替代: T2 贴代码时把 scan 输出里的 literal_val 也以 parallel
    // 数组 kBssLdrbLiteralVals[] 存一份,这里直接 g_libtiny_base + kBssLdrbLiteralVals[pc_idx].

    // 也记录指令的 dst reg(r0-r3 最常见)被 load 之后的值,下游 python 用来
    // 判 "本次 sign 读到 .bss 里是啥"
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "{\"seq\":%d,\"tid\":%d,\"is_sign_tid\":%d,"
        "\"pc\":\"0x%08x\",\"off\":\"0x%x\",\"lr\":\"0x%08x\","
        "\"r0\":\"0x%08x\",\"r1\":\"0x%08x\","
        "\"r2\":\"0x%08x\",\"r3\":\"0x%08x\","
        "\"pc_idx\":%d,\"hit_in_pc\":%d}\n",
        seq, tid, is_sign_tid(tid) ? 1 : 0,
        pc, (uint32_t)(pc - g_libtiny_base), lr,
        r0, r1, r2, r3, pc_idx, hit);
    if (n > 0) bss_ldrb_write(buf, (size_t) n);
}
```

### §5.2 install_thread 里加 install loop

在现有 `libtiny_eor_pre` 的 `shadowhook_intercept_func_addr` 调用**之后**加:

```c
// docs/66 — main-thread .bss ldr probe install loop
ensure_bss_ldrb_log_open();
int bss_ok = 0, bss_fail = 0;
for (size_t i = 0; i < kNumBssLdrbCandidates; i++) {
    uint32_t off = kBssLdrbCandidates[i] & ~1u;
    void* target = (void*)((tb + off) | 1);  // Thumb
    void* stub = shadowhook_intercept_func_addr(
        target, (shadowhook_interceptor_t) bss_ldrb_pre,
        (void*)(intptr_t) i, 0,
        "libtiny.so", "bss_ldrb");
    if (stub == nullptr) {
        log_line("[bss-ldrb] FAIL idx=%zu @ libtiny+0x%x errno=%d msg=%s",
            i, off, shadowhook_get_errno(), shadowhook_to_errmsg(shadowhook_get_errno()));
        bss_fail++;
    } else {
        log_line("[bss-ldrb] INSTALL OK idx=%zu @ libtiny+0x%x stub=%p",
            i, off, stub);
        bss_ok++;
    }
}
log_line("[bss-ldrb] total=%zu OK=%d FAIL=%d log=%s",
    kNumBssLdrbCandidates, bss_ok, bss_fail, kBssLdrbLogPath);

// 再装一个 tiny_dispatch 入口 hook 学 sign tid
void* dispatch_target = (void*)((tb + 0x90795) & ~1u | 1);  // Java_..._t_a
void* dispatch_stub = shadowhook_intercept_func_addr(
    dispatch_target, (shadowhook_interceptor_t) tiny_dispatch_pre,
    nullptr, 0, "libtiny.so", "tiny_dispatch_tid_learner");
log_line("[bss-ldrb] tiny_dispatch learner stub=%p", dispatch_stub);
```

### §5.3 验收 T2

- [ ] 代码无编译错误(T3 会验证)
- [ ] `kBssLdrbCandidates` 长度 = §4 scan 数组长度
- [ ] `g_bss_ldrb_per_pc[128]` 数组足够大(候选 ≤ 60 < 128)
- [ ] 装了 tiny_dispatch tid learner

---

## §6 T3 — 编译 + 验证

```bash
cd /Users/zhao/Desktop/test/xhs/lsposed/xhs-capture
./build.sh 2>&1 | tail -5
# 必须最后一行是 "DONE: ... xhs-capture.apk"
```

编译出错回 §5 检查。常见错:`std::set` 没 include → 在文件顶部加 `#include <set>`。

---

## §7 T4 — 真机跑

### §7.1 clean state(每次跑前,必全做)

```bash
PKG=com.xingin.xhs

# 1. uninstall xhs + 清 sdcard
adb uninstall $PKG
adb shell "su -c 'rm -rf /sdcard/Android/data/$PKG /sdcard/Android/obb/$PKG; rm -f /sdcard/Download/ks.sr0*; find /sdcard -iname \"*xingin*\" -type f -delete 2>/dev/null; find /sdcard -iname \"*xhs*\" -type f -delete 2>/dev/null'"

# 2. install xhs (原版)
adb install -r /Users/zhao/Desktop/test/xhs/target/xhs.apk

# 3. install xhs-capture (带新 probe)
adb install -r lsposed/xhs-capture/build/xhs-capture.apk

# 4. ★★★ reboot ★★★ (Pitfall P1)
adb reboot
adb wait-for-device
adb shell 'while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 2; done'

# 5. 恢复 WiFi + 时间 + 停 VPN
adb shell 'su -c "svc wifi enable; svc data enable; date $(date +%m%d%H%M%Y.%S)"'
adb shell "am force-stop com.tunnelworkshop.postern; am force-stop com.v2ray.ang"
sleep 10
adb shell "ping -c 1 -W 3 8.8.8.8"  # 必须成功
adb shell input keyevent 82  # 解锁
```

### §7.2 Smoke test(§2 协议)

```bash
adb shell "am force-stop com.xingin.xhs"
adb shell "su -c 'rm -f /data/data/com.xingin.xhs/files/*.jsonl /data/data/com.xingin.xhs/files/*.log 2>/dev/null'"
adb shell "monkey -p com.xingin.xhs 1"
sleep 8

# 期望全部满足
adb shell "su -c 'wc -l /data/data/com.xingin.xhs/files/xhs_native_trace.log'"
# 应 > 50 行

adb shell "su -c 'grep -c \"bss-ldrb\\] INSTALL OK\" /data/data/com.xingin.xhs/files/xhs_native_trace.log'"
# 应 ≥ 40 (多数候选装上)

adb shell "su -c 'ls -la /data/data/com.xingin.xhs/files/bss_ldrb_trace.jsonl'"
# 应 > 0 字节

adb shell "pgrep -af com.xingin.xhs"
# xhs 进程必须还在(没 crash)
```

**任一失败 → 回 §7.1 再 reboot,不要跳过**。

### §7.3 清 log 让用户操作

```bash
adb shell "am force-stop com.xingin.xhs"
adb shell "su -c 'rm -f /data/data/com.xingin.xhs/files/*.jsonl /data/data/com.xingin.xhs/files/*.log 2>/dev/null'"
```

然后告诉用户:
1. 从 launcher 打开 xhs
2. 点"同意隐私协议"
3. **必须登录**(真机 t 字段真实在 post-login 才稳定出现)
4. 登录后刷首页 **60 秒**,确保 mua #20+ 覆盖 t 激活窗口
5. 说"停"

### §7.4 pull(用户说"停"后)

```bash
TS=$(date +%s)
CAP=/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures
for NAME in bss_ldrb_trace:jsonl tiny_cmds:jsonl xhs_capture:log xhs_native_trace:log; do
    F="${NAME%:*}"; EXT="${NAME#*:}"
    adb shell "su -c 'cp /data/data/com.xingin.xhs/files/$F.$EXT /sdcard/${F}_bss_$TS.$EXT && chmod 666 /sdcard/${F}_bss_$TS.$EXT'"
    adb pull /sdcard/${F}_bss_$TS.$EXT $CAP/
done
# candidate 列表也复制一份方便 diff 对齐
cp bss_ldrb_candidates.json $CAP/bss_ldrb_candidates_$TS.json
ls -la $CAP/*_bss_$TS.*
```

### §7.5 验收 T4

- [ ] `bss_ldrb_trace_bss_$TS.jsonl` **> 500 行**
- [ ] `xhs_capture_bss_$TS.log` **> 5 MB**(正常 60s 操作)
- [ ] `tiny_cmds_bss_$TS.jsonl` **> 100 sign calls**
- [ ] `xhs_capture_bss_$TS.log` 里解析 mua,**至少一条有 `"t":{...}`**(否则 t 没激活成功,用户登录后没刷够久)

---

## §8 T5 — Python diff 找 t gate

### §8.1 解析 bss_ldrb hits + 提取 sign 窗口

```python
#!/usr/bin/env python3
"""docs/66 §8: diff sign-with-t vs sign-without-t 读到的 .bss 值,找 t gate flag"""
import json, re, base64, collections

TS = 'XXXX'  # 填你的 timestamp
CAP = '/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures'

# 1. 读 bss trace
bss = []
with open(f"{CAP}/bss_ldrb_trace_bss_{TS}.jsonl") as f:
    for l in f:
        try: bss.append(json.loads(l))
        except: pass

# 2. 过滤 sign tid
sign_tids = {b['tid'] for b in bss if b['is_sign_tid']}
print(f"sign tids learned: {sign_tids}")
bss_sign = [b for b in bss if b['tid'] in sign_tids]
print(f"bss hits in sign threads: {len(bss_sign)} / {len(bss)}")

# 3. 解析 mua 时间戳 + has_t
log = open(f"{CAP}/xhs_capture_bss_{TS}.log", errors='replace').read()
muas = []
for m in re.finditer(r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\]\s+>\s+x-mini-mua:\s+([A-Za-z0-9_\-\.]+)', log):
    p = m.group(2).rstrip('.').split('.')[0]
    pad = '=' * ((4 - len(p) % 4) % 4)
    try:
        js = json.loads(base64.urlsafe_b64decode(p + pad))
        muas.append({'ts': m.group(1), 'c': js.get('c'), 'has_t': 't' in js, 'json': js})
    except: pass

# 4. 读 sign cmd 序列(tiny_cmds.jsonl)
signs = []
with open(f"{CAP}/tiny_cmds_bss_{TS}.jsonl") as f:
    for l in f:
        try:
            j = json.loads(l)
            if j.get('cmd') == -1750991364: signs.append(j)
        except: pass

# 5. 对齐 sign 和 mua — 第 i 个 sign 对应第 i 个 mua
print(f"\n{'#':>3} {'c':>3} has_t  bss_reads (pc, r_loaded≈value)")
for i, (s, m) in enumerate(zip(signs, muas), 1):
    if i > 25: break
    # bss 读落在 sign 开始前后 20 条的
    near = [b for b in bss_sign if abs(b['seq'] - s['seq']) < 200]
    # 取 pc_idx 唯一,每个 PC 第一次读到的 r0-r3(最接近 load target 的 dst reg)
    summary = {}
    for b in near:
        if b['pc_idx'] not in summary:
            summary[b['pc_idx']] = b
    summary_str = ' '.join(f"pc={b['off']}→r0={b['r0']}" for b in list(summary.values())[:3])
    print(f"#{i:>3} c={m['c']:>3} t={'Y' if m['has_t'] else '-'}  {summary_str}")

# 6. ★ 核心 diff: 找 "首次 has_t=Y 的 sign" vs "前一个 has_t=- 的 sign" 读到的值差异
first_t_idx = next((i for i, m in enumerate(muas) if m['has_t']), None)
if first_t_idx is None or first_t_idx == 0:
    print("\n⚠ no clean t transition found; try longer trace")
else:
    before_sign = signs[first_t_idx - 1]
    after_sign = signs[first_t_idx]
    before_reads = {b['pc_idx']: b for b in bss_sign
                    if before_sign['seq'] - 50 < b['seq'] < before_sign['seq'] + 150}
    after_reads  = {b['pc_idx']: b for b in bss_sign
                    if after_sign['seq'] - 50 < b['seq'] < after_sign['seq'] + 150}

    print(f"\n★★★ t TRANSITION: mua #{first_t_idx} (c={muas[first_t_idx-1]['c']},t=-) → #{first_t_idx+1} (c={muas[first_t_idx]['c']},t=Y)")
    print(f"PCs hit in both signs → look for loaded value change:")
    for idx in set(before_reads.keys()) & set(after_reads.keys()):
        b = before_reads[idx]; a = after_reads[idx]
        # r0/r1/r2/r3 之一应该是 load 目标
        for reg in ['r0', 'r1', 'r2', 'r3']:
            if b[reg] != a[reg]:
                print(f"  idx={idx} pc={b['off']}  {reg}: {b[reg]} → {a[reg]}  ← ★ CANDIDATE t GATE FLAG ★")
```

### §8.2 验收 T5

- [ ] 找到至少 1 个 `CANDIDATE t GATE FLAG` 行
- [ ] 该 PC 的 `off` 值能和 §4.2 scan 输出的 candidate 对上
- [ ] 把这个 PC 的反汇编周围 20 条(用 capstone 或 radare2)贴进简报

---

## §9 交付清单

```
lsposed/xhs-capture/captures/
  bss_ldrb_trace_bss_<ts>.jsonl        ★ 主交付, 应 > 500 行
  tiny_cmds_bss_<ts>.jsonl             sign cmd 对齐
  xhs_capture_bss_<ts>.log             mua 对齐(含 c/t 字段)
  xhs_native_trace_bss_<ts>.log        hook install OK/FAIL 清单
  bss_ldrb_candidates_<ts>.json        §4 scan 输出(对齐 pc_idx → literal_addr)
```

简报文件: `docs/67_bss_ldrb_delivery.md`,格式参考 docs/65。

---

## §10 简报 7 条(贴到对话里给我)

1. **真机 libtiny base**: `0x7xxxxxxx`
2. **candidate 数量**: §4 scan 产出 n 个,§7.2 smoke test 装上 m 个(FAIL k 个 — 列 offset)
3. **sign tids 学到的**: `{57, 69, 74, ...}`
4. **bss_ldrb 命中总数**: `N 条`,其中 sign tid 命中 `M 条`(M/N 比例 → 反映 candidate 选得准不准)
5. **sign #N 是首次 has_t 的**: (seq, c 值, URL)
6. **t gate candidate**: §8.1 Python 输出的 "CANDIDATE t GATE FLAG" 那几行,**pc + off + 变化前值 + 变化后值**
7. **反汇编 gate PC 周围 20 条**:用 `objdump -d libtiny.so` 或 capstone 贴那一段,标出 `cmp + b<cond>`

---

## §11 风险 & Fallback

| 风险 | 触发 | Fallback |
|---|---|---|
| §4 scan 0 结果 | TARGET_LO/HI 范围错 | 扩到 `[0x580000, 0x5f0000)`;或扫 `.data`(PT_LOAD WR 段) |
| §7.2 smoke `bss-ldrb` INSTALL 全 FAIL | shadowhook 认不出 Thumb 指令 prologue | 每个 candidate PC 前 `& ~1` 再 `| 1`,已在 T2 代码里做了;若仍 fail 可能是 capstone 解出的 PC 偏移错了 2 字节,scan 时对 PC `~1` 再匹配 |
| §7.2 smoke xhs crash | 候选密集(Pitfall P2) | §4 scan 已做间距过滤,crash 说明间距不够大 → 脚本里 `< 32` 改 `< 64`,重 scan |
| §7.5 mua 全无 t | 用户没登够久 / 未登录 | 让用户重来,刷满 60s+,必要时多翻几个视频详情页 |
| §8 `CANDIDATE t GATE FLAG` = 0 个 | 真实 gate PC 没在 candidate 里 | 扩 §4 scan 范围;或改 §11 fallback: hook 0x90795 入口启动 per-thread single-step 追 100 条指令 |

---

## §12 Why 符合 unidbg 黑盒大方向

- 真机 **只读不改**(shadowhook 读寄存器,不改 libtiny 指令)
- 找到 gate 条件后 **在 unidbg 补环境**(`backend.mem_write` 写 `.bss` 对应值)
- libtiny 自己代码在 unidbg 跑同一分支 → t 字段自然出现
- 不 stub libtiny 任何函数,不绕过任何逻辑

和 docs/60/61/64 一脉相承:shadowhook 观察 → unidbg 补环境。

---

## §13 一句话总结

**docs/65 证明 t gate 不在 sign path 的 6 候选 PC(background thread 写侧),在 main thread 读 `.bss 0x5c****` 的某条 ldr。docs/66 用 capstone 静态反汇编 libtiny.so 列全部这种 ldr 当候选,shadowhook 装上,用动态学的 sign tid 过滤命中,diff "无 t sign vs 有 t sign" 读到的值 → 定位 t gate flag offset → unidbg 补 1 行 `mem_write` 让 t 自然出现。**
