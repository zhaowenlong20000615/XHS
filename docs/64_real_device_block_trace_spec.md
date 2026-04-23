# 需求: 真机 shadowhook 抓 libtiny "t 字段激活" 的分支执行轨迹

**受众**: 负责 LSPosed + shadowhook (`lsposed/xhs-capture/jni/`) 的窗口
**工具**: **纯 shadowhook,不要 Frida** (memory: `project_xhs_capture_approach` — Frida 在 Pixel 6 / Android 15 不 work)
**产出**: `lsposed/xhs-capture/captures/libtiny_t_trace_<ts>.jsonl`
**预期工时**: 2-3 小时 (熟悉 shadowhook 的话)

---

## 0. 一句话摘要

**在真机 libtiny 的 32 个 candidate PC 位置装 shadowhook inline intercept,每次命中记录 `{seq, pc, lr, r0..r7}` 到 jsonl,覆盖 app 启动到 mua 首次含 `"t"` 字段 (~sign #14,真机 seq=689) 的窗口,供 unidbg 侧 diff 反推 t 字段激活 gate。**

---

## 1. 背景 (docs/62/63)

我们 unidbg 端 (纯黑盒) 追 t 字段激活,已:

- **Round 1-14**: 证伪栈 / sl / JNI Java field / per-URL bucket / pthread tid / global bump counter 是 t gate
- **Round 15**: POST_SIGN_TRACKER=1 (sign 后调 cert_list + 0x9657e61c) 激活 tail 累积 (c=11 时 part[1] 576→592,+12B) —— 这是独立机制,**不是** t 字段激活
- **Round 16**: BLOCK_TRACE diff 找到 counter 函数 `lib+0x6e094` + gate `lib+0x1bd086 cbnz r0` + flag @ `lib+0x5c7ac6/ac8`; HOLD_C11_FLAG 强制走 counter path 每次 sign → **t 仍不激活** (JSON 稳定 296/297B)。**counter path ≠ t trigger**。

**结论**: libtiny 里 t 字段激活是**另一条独立 code path**,我们 unidbg 从未进入。OLLVM 加密让字符串 't' 的静态搜索 0 结果 (搜 `movs rX, #0x74` / immediate `#0x74` 全 0 次)。唯一可靠办法是**真机采样 ground truth**: 真机 sign #14 (c=9, cfg/android) **确实**进入 t 激活 code path,我们 diff 真机 vs unidbg 走不同的 PCs 就能定位 gate。

docs/62 已解析:
- 真机 mua #14 首次 t,URL=`as.xiaohongshu.com/api/v1/cfg/android`,c=9,tid=187
- tiny_cmds seq=689,前面 seq=651 (sign #13 c=4 tid=68) 之间有 cert×2 + 9657×2 + d7×20+ + Activity×1 + 9657×3 + d7×4 cmd 序列

---

## 2. Hook 实现

### 2.1 用 shadowhook 的 `shadowhook_intercept_func_addr` API

已经在 `xhscap_hook.cpp` 中示范过 EOR probe (docs/61 `libtiny_eor_pre`)。复用同一模式。

### 2.2 32 个 candidate PC (我们 unidbg diff 出来的 c=11 transition 关键点)

以 libtiny base 为基址,**加 1 变 Thumb**。

```c
// docs/64 — t 字段激活 candidate PC
// 来源: unidbg Round 16 block trace diff (sign c=10 vs c=11)
// 覆盖 counter-increment path + JSON encode path + HashMap put path
static const uint32_t kLibTinyCandidates[] = {
    // ---- counter path (Round 16 定位) ----
    0x06e094,   // counter_inc 函数入口 (lr+0xc += 1)
    0x06df40,   // counter sub-function
    0x06d720,   // counter finalize helper
    0x01bd07c,  // gate 前置 beq (bit-0 flag check)
    0x01bd086,  // gate cbnz r0 (byte flag @ .bss 0x5c7ac6/ac8)
    0x01bd088,  // 进 counter bl
    0x00194750, // 另一 counter caller
    0x000f6810, // 另一 counter caller
    // ---- c=11 transition region 代表性 block ----
    0x0006d22c, 0x0006d720, 0x0006d72a, 0x0006df40, 0x0006df48,
    0x0006e094, 0x0006e0ba, 0x0006e0d2, 0x0006e0f4, 0x0006e128,
    0x0006e34c, 0x0006e6ce, 0x0006f534, 0x0006f5f4, 0x0006f690,
    0x0006f6e4,
    // ---- JSON encode / HashMap put 可能路径 ----
    0x0009f870, // bl 0xb5350 (HashMap.put wrapper call site)
    0x000b5350, // JNI put wrapper entry
    0x00094553, // NewStringUTF wrapper call site (put value)
    0x000b0fff, // NewStringUTF wrapper call site (put key)
    // ---- sign cmd dispatch 入口 (-1750991364) ----
    0x00090795, // Java_com_xingin_tiny_internal_t_a (JNI entry)
    // ---- 可能的 t 激活 gate (猜测) ----
    0x00055ac00,// URL_B 比 URL_A 多走 2 倍的热路径 (bucket lookup 相关)
    0x00054d214,// 类似
    0x0016efbe, // std::map<string,X>::find (红黑树 key lookup)
    0x0008ef44, // HashMap bucket index (fmix + hash % 47)
};
```

**如果觉得 32 太多**,至少先装 **top-10**: `0x1bd07c/86/88, 0x6e094, 0x9f870, 0xb5350, 0x90795, 0x16efbe, 0x8ef44, 0x55ac00`。

### 2.3 inline hook 回调 (shadowhook_cpu_context_t)

```c
static const char* kTraceLogPath = "/data/data/com.xingin.xhs/files/libtiny_t_trace.jsonl";
static atomic_int g_t_trace_seq = 0;
static const int kTTraceCapPerPc = 200;  // 每个 PC 最多 200 次命中,防 log 爆炸
static atomic_int g_t_trace_per_pc[64] = {0};  // 对应 32 个 PC, 保留 64 槽

// per-PC 命中计数索引 = PC 在 kLibTinyCandidates 数组的 index
static void t_trace_pre(shadowhook_cpu_context_t* cpu, void* user_data) {
    int pc_idx = (int)(intptr_t)user_data;
    int hit = atomic_fetch_add(&g_t_trace_per_pc[pc_idx], 1);
    if (hit >= kTTraceCapPerPc) return;

    int seq = atomic_fetch_add(&g_t_trace_seq, 1);
    uintptr_t pc = cpu->arch.arm.pc;
    uintptr_t lr = cpu->arch.arm.lr;
    uintptr_t off = pc - g_libtiny_base;
    uintptr_t lr_off = lr - g_libtiny_base;  // 可能 lr 不在 libtiny 里, 那就打 raw
    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"seq\":%d,\"pc\":\"0x%zx\",\"off\":\"0x%zx\",\"lr\":\"0x%zx\","
        "\"lr_off\":\"0x%zx\",\"r0\":\"0x%x\",\"r1\":\"0x%x\","
        "\"r2\":\"0x%x\",\"r3\":\"0x%x\",\"r4\":\"0x%x\","
        "\"r5\":\"0x%x\",\"r6\":\"0x%x\",\"r7\":\"0x%x\","
        "\"tid\":%d,\"hit_in_pc\":%d}\n",
        seq, pc, off, lr, lr_off,
        cpu->arch.arm.r0, cpu->arch.arm.r1, cpu->arch.arm.r2, cpu->arch.arm.r3,
        cpu->arch.arm.r4, cpu->arch.arm.r5, cpu->arch.arm.r6, cpu->arch.arm.r7,
        gettid(), hit);
    // 写 log (复用现有 log_line 或 fd append)
    t_trace_write(buf);
}
```

### 2.4 安装 loop

```c
for (size_t i = 0; i < ARRAY_SIZE(kLibTinyCandidates); i++) {
    void* target = (void*)((g_libtiny_base + kLibTinyCandidates[i]) | 1);  // Thumb
    void* s = shadowhook_intercept_func_addr(
        target, (shadowhook_interceptor_t)t_trace_pre,
        (void*)(intptr_t)i, 0,
        "libtiny.so", "t_trace_candidate");
    if (s == nullptr) {
        log_line("[t-trace] INSTALL FAIL @ lib+0x%x errno=%d", kLibTinyCandidates[i], shadowhook_get_errno());
    } else {
        log_line("[t-trace] INSTALL OK @ lib+0x%x idx=%zu", kLibTinyCandidates[i], i);
    }
}
```

### 2.5 注意事项

- **Thumb 模式**: 所有 PC 要 `| 1` 再传给 shadowhook_intercept_func_addr
- **某些 PC 可能 install fail** (OLLVM 混淆打乱 prologue,shadowhook 无法识别)。失败的不影响其他。
- **同一 PC 被多次命中** 很常见 (counter 循环等),per-PC 限 200 够用。
- **不要 hook 太多** (>50 个) 以免 install 超时或进程 crash。

---

## 3. 运行步骤 — **必须严格 clean state** (docs/55 + memory `feedback_spec_must_require_clean_state`)

**不满足任何一条都不算有效样本,前面的调试会走弯路**:

### 3.1 前置 (每次跑前)

```bash
# 1. 完全卸载 xhs,清磁盘缓存
adb uninstall com.xingin.xhs
adb shell "su -c 'rm -rf /sdcard/Android/data/com.xingin.xhs /sdcard/Android/obb/com.xingin.xhs /storage/emulated/0/xhs* 2>/dev/null'"
adb shell "su -c 'pm uninstall --user 0 com.xingin.xhs 2>/dev/null'"

# 2. 重启手机 (LSPosed scope 持久化)
adb reboot
# 等 30s 起来
sleep 60

# 3. 重新安装 xhs 原版 apk (不用我们改过的)
adb install build/inspect/xhs-app-release.apk  # 或项目里 release 原版

# 4. 重装 LSPosed xhs-capture (带新 t_trace probe)
cd lsposed/xhs-capture
bash build.sh
adb install -r build/xhs-capture.apk

# 5. **再**重启手机 (xhs-capture scope 生效必须 reboot)
adb reboot
sleep 60

# 6. 确认飞行模式关 (我们要真 TLS 握手)
adb shell settings put global airplane_mode_on 0
adb shell am broadcast -a android.intent.action.AIRPLANE_MODE
```

### 3.2 跑

```bash
# 冷启 xhs
adb shell 'am force-stop com.xingin.xhs; monkey -p com.xingin.xhs -c android.intent.category.LAUNCHER 1'

# **必须登录** (真机 sign #14 t 出现在登录后的 cfg/android)
# 手机上手动完成登录 (短信验证码)

# 等待 app 充分跑完 (至少 30 秒, 覆盖 sign #14+)
sleep 40
```

### 3.3 pull 数据

```bash
TS=$(date +%s)
adb shell "su -c 'cp /data/data/com.xingin.xhs/files/libtiny_t_trace.jsonl /sdcard/t_trace_$TS.jsonl && chmod 666 /sdcard/t_trace_$TS.jsonl'"
adb pull /sdcard/t_trace_$TS.jsonl lsposed/xhs-capture/captures/libtiny_t_trace_$TS.jsonl
```

---

## 4. 验收标准

### 4.1 完整性

```bash
F=lsposed/xhs-capture/captures/libtiny_t_trace_<ts>.jsonl
wc -l $F   # 期望 > 500 行 (32 PC × 多次命中)
# 每个 PC 至少 1 次命中 (除了 install fail 的)
python3 -c "
import json, collections
c = collections.Counter()
for line in open('$F'):
    try: j = json.loads(line); c[j['off']] += 1
    except: pass
for off, n in sorted(c.items()):
    print(f'{off}: {n}')
"
```

### 4.2 覆盖 sign #14 窗口

同时 pull `tiny_cmds.jsonl`,确认 sign cmd seq=689 出现:

```bash
adb pull /data/data/com.xingin.xhs/files/tiny_cmds.jsonl lsposed/xhs-capture/captures/tiny_cmds_$TS.jsonl
python3 -c "
import json
c = [json.loads(l) for l in open('lsposed/xhs-capture/captures/tiny_cmds_$TS.jsonl')]
signs = [x for x in c if x['cmd'] == -1750991364]
print(f'sign count: {len(signs)}')
print(f'first t-enabled sign would be #14 (seq~689)')
print(f'first sign seq: {signs[0][\"seq\"] if signs else \"?\"}')
print(f'14th sign seq: {signs[14][\"seq\"] if len(signs) > 14 else \"not reached\"}')"
```

### 4.3 验证 t 字段激活

`xhs_full.log` 里前 N 个 mua 的 JSON 应有 `"t":{...}` 出现 (约 #14 起):

```bash
python3 -c "
import re, base64
with open('lsposed/xhs-capture/captures/xhs_full_$TS.log') as f:
    muas = re.findall(r'x-mini-mua:\s*([A-Za-z0-9_\-\.]+)', f.read())
for i, mua in enumerate(muas[:20]):
    parts = mua.rstrip('.').split('.')
    pad = '=' * ((4 - len(parts[0]) % 4) % 4)
    js = base64.urlsafe_b64decode(parts[0] + pad).decode()
    t = 'Y' if '\"t\":' in js else '-'
    c = re.search(r'\"c\":\s*(\d+)', js)
    print(f'#{i:3d} c={c.group(1) if c else \"?\"} t={t} len={len(js)}')"
# 期望: 前 14 个 t='-', 第 15 个 (idx=14) 起 t='Y'
```

---

## 5. 简报必写

拉回文件后,简报回给 unidbg 侧 (我) 包含:

1. **真机 libtiny base**: `0x7xxxxxxx` (每次启动不同)
2. **32 个 PC 的命中次数**: 哪些命中哪些 0 次
3. **是否有 install FAIL**: 列出 fail 的 offset + errno msg
4. **sign #14 的 tid**: 和我们 docs/63 记录的 tid=187 一致吗
5. **前 20 个 mua 的 c/t/len 表**: 确认 t 字段真机按预期激活

---

## 6. 拿到数据后 unidbg 侧做什么

Python diff:

1. 解析 `libtiny_t_trace.jsonl`,按 `hit_in_pc` 排序找 **real device sign #14 时 hit,但 unidbg sign #9 (c=11) 不 hit** 的 PCs
2. 这些 PCs 就是 **t 激活独有** 的分支点
3. 反汇编找 `cmp + b<cond>` 的 gate 条件
4. Gate 条件是什么 (某 byte flag / heap ptr 非空 / 某 counter 达阈值),就在 unidbg 里**补这个条件** (mem_write 或 CodeHook)
5. 验证: 补条件后 mua JSON 应出现 `"t":{` 且长度 ~343B

---

## 7. Why 这符合大方向 (纯 unidbg 黑盒)

- 我们**不改 libtiny 一条指令**,只在真机**观察**哪些 PC 被 t 激活 code path 触发
- 得到 PC 后,在 unidbg 里**补环境** (设 flag / populate heap / stub JNI) 让相同分支在 unidbg 被走到
- 和 docs/60/61 EOR probe 是同一套 shadowhook 工作流
- 数据路径: **真机观察 → 反推条件 → unidbg 补环境**,保持"黑盒"性质

---

## 8. 风险和 fallback

### 8.1 风险 A: 32 个 PC 某些 install fail

OLLVM 混淆区 shadowhook 可能拒装. Fallback:
- 只装 install OK 的 (ignore fail)
- 如果 < 10 个 OK, **简化为 hook top-5**: `0x1bd086, 0x6e094, 0x9f870, 0x90795, 0x16efbe`

### 8.2 风险 B: trace 打太多日志导致 app 卡顿

per-PC cap 200 应足够. 如果仍慢, 降到 cap 50.

### 8.3 风险 C: 登录不成功 (xhs 反检测触发封号)

如果手机被封号/强制验证码,切一个**从未登过 xhs** 的号码。真机反检测见过一次需要换号/换设备。

---

## 9. 交付清单

```
lsposed/xhs-capture/captures/
  libtiny_t_trace_<ts>.jsonl         # 主 probe 输出,500+ 行
  tiny_cmds_<ts>.jsonl               # cmd 流水对齐
  xhs_full_<ts>.log                  # HTTP + mua 对齐
  real_device_libtiny_base_<ts>.txt  # 一行 "libtiny.so: 0x7xxxxxxx"
```

简报贴到对话里我这边就能开始 unidbg 侧 diff。
