# 需求: 真机 shadowhook 抓 libtiny+0x96000 的 r0/r1 值

**受众**: 负责 LSPosed + shadowhook (`lsposed/xhs-capture/jni/shadowhook/`) 的窗口
**工具**: 纯 shadowhook, 不要 Frida (memory `project_xhs_capture_approach`)
**产出**: `lsposed/xhs-capture/captures/real_eor_probe_<ts>.jsonl`
**预期工时**: 1-2 小时 (你们熟悉 shadowhook 的话)

---

## 0. 1 句话摘要

**在真机 libtiny+0x96000 (EOR r2,r0,r1) 位置装 shadowhook inline hook, 每次调用时记录 r0 r1 r2 三个寄存器值, 连续抓前 100 次 d7.a crash site 执行。**

---

## 1. 背景 (docs/58/59)

docs/59 诊断 unidbg 里 d7.a (cmd 1140071423) crash 在 libtiny+0x96000:
```
lib+0x95ffc: LDRD r1, r2, [r1]      ; r1 = *(src)
lib+0x96000: EOR  r2, r0, r1         ; r2 = r0 XOR r1 = real_func_ptr
lib+0x96004: LDR  r0, [r6, #0xd4]    ; arg1
lib+0x96008: LDR  r1, [r6, #0xc4]    ; arg2
lib+0x9600c: BLX  r2                  ; call real_func
```

我们 unidbg 实测:
- r0 = **0** (from `*(lib+0x5c41d8)` which is 0)
- r1 = 0x79866f14 (OLLVM 加密的指针)
- XOR = 0x79866f14 (未解密, 跳 unmapped → crash)

**问题**: 真机同位置 r0 应为非零掩码, XOR 后得真 libtiny 函数地址。我们需要:
- 真机 r0 是什么 (mask 值)
- 真机 r1 是什么 (与我们同样的加密值吗?)
- 真机 r2 = r0 XOR r1 解密后指向哪个函数 (libtiny+? offset)

这 3 个值出来, 我们就能:
1. 反向工程出 `*(lib+0x5c41d8)` 应该是什么值
2. 在 unidbg `XhsCombinedSigner.initialize()` 里 mem_write 补上
3. d7.a 不再 crash
4. cptr populate → mua 长到 1337B → 突破 2/5

---

## 2. Hook 实现

### 2.1 Hook 点

真机 libtiny base 从 xhs_capture.log 的 `[bss] libtiny base = 0x...` 查。**每次进程 startup 不同**, 所以要用相对 offset 动态算。

Hook 地址: `libtiny_base + 0x96000`

Thumb 模式, 需要 `| 1` 传给 shadowhook (`0x96000` + 1 = `0x96001`)。

### 2.2 shadowhook 伪代码

```c
// xhs-capture 的 jni 模块已经有 shadowhook 框架, 在 jni/ 里扩展
#include "shadowhook.h"

static void *orig_eor_insn = NULL;

// shadowhook 的 INLINE hook 会在指令执行前触发回调
// 用 args_fn 拿到 arm32 寄存器
void on_eor_hit(arm_regs_t *regs, void *context) {
    static int seq = 0;
    if (seq >= 100) return;
    
    write_to_log(SEQ, regs->r0, regs->r1, regs->r2, regs->r3,
                 regs->r4, regs->r5, regs->r6, regs->lr);
    seq++;
}

void install() {
    uintptr_t libtiny_base = get_libtiny_base();   // 从 /proc/self/maps 读
    uintptr_t target = libtiny_base + 0x96000 + 1; // +1 = Thumb
    
    shadowhook_hook_sym_addr(
        (void*)target,
        (void*)eor_stub_func,   // stub 收集 regs, 调 on_eor_hit
        &orig_eor_insn
    );
}
```

**关键注意**: shadowhook 的 inline hook 默认可能修改 2+ 指令。0x96000 附近是 OLLVM 加密代码, hook 可能破坏原指令语义 → 需要 `SHADOWHOOK_IS_SHARED_MODE` 或用 plt hook 模式。

**备选方案**: 如果 inline hook 在 0x96000 不稳, 退到 plt hook 或 FunctionAddrHook 模式。shadowhook 高版本有 `shadowhook_hook_insn_addr` 能精确 hook 单指令。

如果 shadowhook 不能 precisely hook 单条 Thumb EOR, **退而求其次**:
- hook **BLX r2** 在 0x9600c (+1 = 0x9600d Thumb)
- 此时 r0/r1 已被覆盖 (装载 arg1/arg2), 但 **r2 = XOR result = real function ptr**
- 只记 r2 一个值即可反推 mask

更简化:
- 只在 lib+0x9600c 装 hook, 记录 r2
- r2 = 真机的 real_func_ptr
- 我们 unidbg 的 r1 加密值已知 (0x79866f14)
- real device r1 加密值假设和我们一样 (来自同一个静态编码 table)
- **mask = real_r2 XOR 0x79866f14**
- 我们直接把 mask 写到 lib+0x5c41d8 + 指针结构

**所以 hook r2 at 0x9600c 一次够用!**

### 2.3 输出 jsonl 格式

每次 hook 一条:
```json
{"seq":0, "ts_ms":42, "libtiny_base":"0x7c640000",
 "r0":"0x...", "r1":"0x...", "r2":"0x...",
 "r3":"0x...", "r4":"0x...", "r5":"0x...", "r6":"0x...",
 "lr":"0x..."}
```

---

## 3. 运行步骤 (遵循 docs/55 纯净条件)

真机必须**完全 fresh install** 并**登录**, 因为 d7.a 只在 app startup 前 46 次左右密集调用, 冷启抓 Ctrl-C。

```bash
# fresh install (复用 docs/55 清理脚本)
bash /Users/zhao/Desktop/test/xhs/scripts/fresh_clean.sh  # 若有, 否则照 docs/55 §2.1

# 装带 shadowhook EOR probe 的 xhs-capture
adb install -r lsposed/xhs-capture/build/xhs-capture.apk
adb reboot; adb reboot (double)

# 冷启 + 登录 + 等 10s
adb shell 'am force-stop com.xingin.xhs; monkey -p com.xingin.xhs -c android.intent.category.LAUNCHER 1'
# (手动登录)
sleep 15

# pull 输出
TS=$(date +%s)
adb shell "su -c 'cp /data/data/com.xingin.xhs/files/real_eor_probe.jsonl /sdcard/eor_$TS.jsonl && chmod 666 /sdcard/eor_$TS.jsonl'"
adb pull /sdcard/eor_$TS.jsonl /Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/real_eor_probe_$TS.jsonl
```

---

## 4. 交付验收

### 4.1 文件基本
```bash
F=/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/real_eor_probe_<ts>.jsonl
wc -l $F  # 应 >= 30 行
```

### 4.2 r2 值的有效性
```bash
python3 -c "
import json
xs = [json.loads(l) for l in open('$F')]
r2s = set(int(x['r2'], 16) for x in xs)
libbase = int(xs[0]['libtiny_base'], 16)
print(f'unique r2 values: {len(r2s)}')
for r in sorted(r2s)[:10]:
    off = r - libbase
    print(f'  r2=0x{r:x} = libtiny+0x{off:x}')
"
```

**期望**: 
- r2 值 ≥ libtiny_base (0x7xxxxxxx 级)
- 多次调用可能返同一个 r2 (都调相同 callback) 或几个不同值

### 4.3 mask 反推
```bash
python3 -c "
import json
xs = [json.loads(l) for l in open('$F')]
libbase = int(xs[0]['libtiny_base'], 16)
# 假设 unidbg 的 r1 加密值也是 0x79866f14 — 只要 r1 一致, mask 就是 r1 XOR r2
# unidbg r1 = 0x79866f14 (fixed from static table)
for x in xs[:5]:
    r1 = int(x.get('r1', '0'), 16)
    r2 = int(x['r2'], 16)
    mask = r1 ^ r2
    print(f\"seq={x['seq']} r1=0x{r1:x} r2=0x{r2:x} mask=0x{mask:x}\")
"
```

把 mask 值贴简报里给我。

---

## 5. 简报必写

1. 真机 libtiny base 地址
2. r0, r1, r2 的典型值 (前 5 次)
3. 反推的 mask (= r1 XOR r2)
4. shadowhook 类型 (inline/insn/plt)
5. 冷启是否有 crash
6. 是否登录了

---

## 6. 拿到数据后我做什么

1. mask 值 + 0x79866f14 XOR 验证 → 得 real_func_addr
2. 在 unidbg `XhsCombinedSigner.initialize()` 里:
   ```java
   // patch lib+0x5c41d8 指向含 mask 的 struct
   // struct: { uint32_t mask_low, uint32_t mask_high, ... }
   // 分配 16 字节, 写 mask, 存 pointer 到 bss
   long structAddr = ... malloc;
   backend.mem_write(structAddr, maskBytes);
   backend.mem_write(tinyBase + 0x5c41d8, addrLE);
   ```
3. 跑 MuaTailProbeTest 看 d7.a 不 crash
4. 调 d7.a 46 次, 看 cptr bucket 填
5. live server test 看 3/5 破几个

---

## 7. Why 这符合大方向

- 观测真机 (shadowhook inline hook 不改 app, 纯读寄存器)
- 把观测到的 mask 填 unidbg memory (补环境)
- libtiny 在 unidbg 自己基于这个 mask 跑后续代码, 我们**不改它一条指令**
- 46 次 d7.a 让 libtiny 自己 populate cptr, **不编造 bucket**

和 docs/51-56 的 trace/diff 路径一脉相承, 只是这次探针更精确。
