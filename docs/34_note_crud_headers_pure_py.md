# note CRUD 头字段 — 纯 Py 化进度（2026-04-15）

基于抓包文件 `lsposed/xhs-capture/captures/xhs_capture_20260413_162400.log`
（session2，361 次请求，9 个不同的 note CRUD 端点，全部 200）

## 本轮目标

用户要求：针对 note CRUD 的请求头，**每个字段都先分析再静态逆向 + 复写 Py**。

## 方法

1. 从 lsposed 抓包解析每个 note 端点的完整请求头集合，用 Python 脚本统计
   每个头的 per-request 可变性（CONST / VAR）
2. jadx 字符串字面量交叉验证，锁定每个头的 Java 侧 / 原生侧出处
3. 对 Java 侧生成的字段直接字节级复写到 Python
4. 对原生生成的字段调 Ghidra headless 反编译分析

## 端点清单（9 个命中）

| Endpoint | N | 方法 |
|---|---:|---|
| `/api/sns/v1/note/detailfeed/preload` | 25 | POST |
| `/api/sns/v4/note/user/posted` | 19 | GET |
| `/api/sns/v1/note/metrics_report` | 15 | POST |
| `/api/sns/v5/note/comment/list` | 12 | GET |
| `/api/sns/v2/note/widgets` | 10 | POST |
| `/api/sns/v1/note/imagefeed` | 5 | GET |
| `/api/sns/v4/note/comment` | 3 | POST |
| `/api/sns/v1/note/like` | 2 | POST |
| `/api/sns/v1/note/collect` | 1 | POST |

## 头字段分类 + 状态

### ✅ 纯 Py 已完成（byte-exact）

| 头 | 来源 | 位置 | 备注 |
|---|---|---|---|
| `X-B3-TraceId` | Java 生成 | [zlb/n0.java:70-85](../target/jadx_out/sources/zlb/n0.java#L70-L85) → `v29.a.a()` | nibble-interleave + 累积右移 |
| `x-xray-traceid` | Java 生成 | [zlb/n0.java:93-114](../target/jadx_out/sources/zlb/n0.java#L93-L114) → `v29.b` | `(ts<<23\|ctr):016x + rnd:016x` |
| `xy-common-params` | Java 构造 | [zlb/j0.java:54-334](../target/jadx_out/sources/zlb/j0.java#L54-L334) | 35 字段 URL-encoded，HashMap bucket order |
| `x-legacy-did` | Java 读取 | [r76/a.java:32](../target/jadx_out/sources/r76/a.java#L32) → `kka.r.e()` | SharedPreferences 或 UUIDv3(android_id) |
| `x-legacy-sid` | Java 读取 | [r76/a.java:33](../target/jadx_out/sources/r76/a.java#L33) → `z76.q0.b()` | /activate 返回的 session token |
| `x-legacy-fid` | Java 读取 | r76/a | 通常空串 |
| `xy-platform-info` | 重建 | (见下) | `platform=android&build=<int>&deviceId=<uuid>`，实际主 API 仍然带这个头，与先前 agent 推断相反 |
| `xy-direction` / `xy-scene` | 会话常量 | 从抓包固化 | 实际上来自 libtiny 返回的 Map，但在 session 内稳定 |
| `User-Agent` / `Referer` | 硬编码 | 客户端常量 | 不需签名 |

**验证**：`xy-common-params` 对 t=1776068490 的真机抓包做了字节级比对，**811 字节完全一致**。

纯 Py 代码见 [unicorn/py_signer/](../unicorn/py_signer/)：
- [device_profile.py](../unicorn/py_signer/device_profile.py) — 会话级常量容器
- [trace_ids.py](../unicorn/py_signer/trace_ids.py) — X-B3-TraceId / x-xray-traceid
- [xy_common_params.py](../unicorn/py_signer/xy_common_params.py) — 35 字段 builder（order 定死）
- [legacy_headers.py](../unicorn/py_signer/legacy_headers.py) — x-legacy-* + xy-platform-info
- [__init__.py](../unicorn/py_signer/__init__.py) — `sign_note_crud()` 汇总入口

### ⚠️ 纯 Py 暂缓 — 保留 Unicorn 兜底

原因：静态 RE 投入产出比过低，见「libtiny 静态 RE 受阻原因」。

| 头 | 源库 | 目前状态 |
|---|---|---|
| `x-mini-sig` | libtiny.so | Unicorn 模拟可用，sig[16:32] 的 SHA-256 公式已纯 Py |
| `x-mini-s1` | libtiny.so | Unicorn 模拟可用 |
| `x-mini-mua` | libtiny.so + Android KeyStore | Unicorn 模拟可用；RSA 尾在 TEE，**永远不可能纯 Py** |
| `x-mini-gid` | libtiny.so | 会话级常量，抓包复用即可 |

### ⚠️ 下一步 Ghidra 目标 — libxyass shield inner_hash

| 头 | 源库 | 说明 |
|---|---|---|
| `shield` | libxyass.so intercept() | 5 步 pipeline 的 4/5 步已纯 Py，只差一个内层 hash 函数 |

## Java 侧拦截链（jadx 确认）

OkHttp 拦截器栈从上到下：

1. **`r76/a.java` TinyInterceptor** ([file](../target/jadx_out/sources/r76/a.java))
   - 读 `x-legacy-did` / `x-legacy-sid`
   - 调 `ega.f.j(method, url, body)` → `com.xingin.tiny.internal.d3.b(-1750991364, ...)` → libtiny native → 返回 `Map<String,String>`，把 entries 逐个 setHeader
   - libtiny 注入的 key 集合（Java 侧看不到字符串字面量，全部由 native 侧 put 进 HashMap）包括 `x-mini-sig`, `x-mini-mua`, `x-mini-s1`, `x-mini-gid`, `xy-direction`, `xy-scene`

2. **`zlb/n0.java`** ([file](../target/jadx_out/sources/zlb/n0.java)) — 注入 `X-B3-TraceId` / `x-xray-traceid`

3. **`zlb/j0.java` 路径**（通过 [ylb/l6.java:28](../target/jadx_out/sources/ylb/l6.java#L28) 的 builder）—
   注入 `xy-common-params`，35 字段硬编码于 `zlb/j0.java:54-334`

4. **`XhsHttpInterceptor`** ([file](../target/jadx_out/sources/com/xingin/shield/http/XhsHttpInterceptor.java))
   - 调 `com.xingin.shield.http.Native.intercept(chain, cPtr)` → **libxyass.so**
   - libxyass 注入 `shield` + `xy-platform-info`
   - 加载器 [jaa/c.java:23](../target/jadx_out/sources/jaa/c.java#L23) 从字节数组 `{120, 121, 97, 115, 115} = "xyass"` 加载

## libtiny 静态 RE 受阻原因

用 `Ghidra/support/analyzeHeadless` 在现有项目
`scratch/ghidra_work/proj_libtiny` 上跑了两个脚本：

1. **`AnswerInterfaceQuestions.java`** — 列 JNI 符号 / 内存布局 / 搜索字符串
   - 只有 1 个导出符号：`JNI_OnLoad @ 0x000c22b4`
   - 所有候选 dispatch cmd 常量（`-1750991364`, `-378830707`, `617278119`,
     `1027279761`, `-872198405`）**都不在任何指令的立即数里**
     → 说明调度表是运行时构造或数据段中的哈希表
   - 字面量搜索：`x-mini-sig`, `x-mini-s1`, `x-mini-mua`, `x-mini-gid`
     **全部 NOT FOUND**
     → header 名字在 .rodata 里不存在，是运行时 XOR/RC4 解密的
     （和 ega/f.java:199-203 里看到的 `c7.a(...)` 解密模式一致）

2. **`DumpJniOnLoad.java`** — 反编译 JNI_OnLoad + 扫描 JNINativeMethod 数组
   - JNI_OnLoad 只有一条间接跳转：
     ```c
     UNRECOVERED_JUMPTABLE = *(DAT_000c2678 + 0xc22e2) + -0x3e5ad44;
     (*UNRECOVERED_JUMPTABLE)(...)
     ```
     Ghidra 完全无法还原
   - `.data.rel.ro` + `.data` + `.rodata` 扫描 JNINativeMethod 三元组
     （`name_ptr, sig_ptr, fn_ptr`）→ **零命中**
     → 方法表不在任何可读数据段里，要么运行时构造要么加密

**结论**：libtiny 的纯 Py 路径至少要：
1. 破解 .rodata 的字符串解密层（XOR/RC4/cert-hash 门控）
2. 还原 JNI_OnLoad 运行时间接跳转的目标
3. 还原 dispatch cmd 的哈希表或 VM 调度器
4. 再啃 byte-mixer 的 CFG-flatten

任何一步都要数天到数周。**保留 Unicorn 模拟是短期最优解**。

## libxyass 静态 RE 进展（本轮实跑）

### 锁定的坐标

- `intercept()` JNI 函数入口 = libxyass.so + **0x23e54**（2682 字节），来自
  之前会话 [DecompileIntercept.java:16](../scratch/ghidra_work/DecompileIntercept.java#L16)
  已锁定的 4 个 JNI 方法地址 `{0x1f454, 0x23e54, 0x25f68, 0x262ec}`
  之一（通过函数大小和入参数量与 jadx 侧的
  `destroy / initialize / initializeNative / intercept` 对应）

### Ghidra headless 跑的结果

| 脚本 | 目标 | 结果 |
|---|---|---|
| `AnswerInterfaceQuestions.java` | 列 JNI 符号 / 搜索 shield 相关字面量 | `shield` / `xy-common-params` / `xy-platform-info` / `intercept` / `XhsHttpInterceptor` 字面量**全部 NOT FOUND** — 运行期解密 |
| `DumpJniOnLoad.java` | 反编译 JNI_OnLoad + 扫 `JNINativeMethod` | 反编译可读；但 `+0x3a1c95a8` 固定偏移 + `(code*)(DAT+0x666e4b10)` 解密入口 → 需要先破解解密函数才能静态追出 fn 地址；**扫不到任何 JNINativeMethod 三元组** |
| `DecompileIntercept.java` | 反编译 `jni_method1 @ 0x23e54` | 2682 字节的函数 Ghidra 只吐出 80 行 C 代码——结尾处 `__stack_chk_fail()` 提前终结，**函数体被 Ghidra 的 jumptable/CFG 分析卡死** |
| `ResolveNativeMethods.java` | 用 p-code 追 RegisterNatives 参数 | 成功定位 `RegisterNatives CALLIND @ 0x2f0fa`（env vtable offset `0x35c = idx 215`），但参数是栈上临时变量（`unique:0x12e700`），需要展开更多 STORE 才能看到实际 `{name, sig, fn}` |

### 本轮用 capstone 的静态反汇编 + helper 跟踪

对 2682 字节的 intercept() 做了完整反汇编（1032 条 thumb 指令）：

- **无内联 crypto magic 常量**：SHA-1/SHA-256/MD5 的 IV、HMAC pad、SHA-256 K 表
  全部没有作为立即数出现，也没有 `movw + movt` 组合出来
- **没有 CFG flatten**：0 个 `mov pc, rN` 指令（和 JNI_OnLoad 不同）
- **62 个直接 bl 调用** + **30 个间接 blx rN**
- 13 个去重的直接 bl 目标：
  `0xd7a4 0xd7f0 0xd9a8 0xdff0 0xe0c8 0x1a170 0x1edf8 0x1ee34 0x1ee70 0x24a1c 0x250f4 0x26714 0x26c6c`
  - `0xd7a4 / 0xd7f0` = 分配器（我们在 JNI_OnLoad 中见过）
  - `0xdff0 / 0xe0c8` = 字符串解密 + lookup
  - 其余是 intercept 的业务 helpers
- **递归扫 85 个 bl 后代函数**，**全部 0 个 crypto 常量命中**
  → 哈希原语要么被 XOR 拆成位运算、要么存在 .bss 的解密字节表里、要么根本不是标准 SHA/MD5

### 间接调用分析（`blx r3` 的 30 个点）

对 intercept 里每个 `blx rN`，capstone 的前向 def 追踪显示三类模式：

1. **JNI vtable calls** — `ldr rN, [r0, #0x390/#0x29c/#0x2a4/#0x2a8]`
   其中 r0 = env。这些是标准 JNI 回调（`CallObjectMethodA`, `GetByteArrayElements` 等）
2. **C++ this-ptr vtable calls** — `ldr rN, [r0, #0x40/#0x44/#0x4c/#0x5c]`
   r0 是 chain/request 对象的 this 指针，这是 OkHttp 的 builder 链式调用
3. **`add rN, rX, fp`** 模式 —— fp（r11）在 prologue 只被保存没有重新初始化，
   后期 capstone 线性反汇编可能把函数末尾的**literal pool** 字节错解成这个模式
   （intercept 有一条 `ldr r0, [pc, #0x378]` 指向 pc+0x378+4 ≈ **0x24260**
   正好在函数中段——这里很可能嵌了一段 literal pool）

### 已存在但数据污染的 ground truth

之前会话 dump 过 ctx_pre / ctx_final（Frida hook），用于验证 HMAC-SHA1 假设
（[scratch/ghidra_work/verify_hmac_sha1_hypothesis.py](../scratch/ghidra_work/verify_hmac_sha1_hypothesis.py)）。
本轮重跑发现：

- **ctx_final[40:60] 在 3 个不同 message 下完全一致**（`608d38c4a274d8d6abdd571f72dc1aa684561b78`）
- SHA-1 的 H 状态不可能跨消息相同——**trace 点位抓错了**
- 所以之前的 HMAC-SHA1 验证失败**不是算法猜错，而是 ground truth 被污染**

→ 没有干净的 (canonicalize, shield_tail) 样本前，静态 RE 无法自证算法是否正确

### 静态硬 blocker 清单（按阻塞面从大到小）

1. **字符串 + 函数指针解密层**：libxyass 在 JNI_OnLoad 时用一个固定 delta
   `0x666e4b10` 函数（`(code*)(iVar9 + 0x666e4b10)`）在原地解密 .bss 中的
   ciphertext blob。破掉它能一次解开所有 native 方法的 name/sig/fn 以及
   intercept 内部的所有字符串。**这是所有下游工作的前置**。
2. **.bss 调度表**：intercept 的 30 个间接 blx 调用里，部分通过 fp/r6-relative
   偏移从 .bss 里读取函数指针。这些指针要等 JNI_OnLoad 跑完才有值。
3. **CFG flatten（可选）**：JNI_OnLoad + 一些 init 函数用 `mov pc, rN`
   计算跳转，但 intercept 自身没有。不是 intercept 的阻塞。

### 下一步（当真能做的 3 件事）

1. **反编译 `0xdff0` 和 `0xe0c8`（字符串解密/lookup）**
   这是最小的可动作单元。如果能独立理解这两个函数，就可以 port 到 Python
   并在离线状态下解密 libxyass 的所有 ciphertext blob，包括 JNI 方法名
   / sig / fn 地址 / shield 内部字符串。那之后 intercept 的 Ghidra decomp
   才有可能看出 `shield` 这个 literal 的 xref，反推 canonicalize 格式。

2. **读 `scratch/ghidra_work/probe_26c6c*.py`**
   这些脚本之前探测 0x26c6c 为可能的 hash 点位。0x26c6c 在 intercept 的
   13 个直接 bl 目标里。如果之前已经跑过 Unicorn 模拟并部分验证，可能有
   遗留结论，能把我省下一大段反编译时间。

3. **采集一批干净的 (canonicalize_bytes, shield) 对样本**
   要么从 `capture/session1_*.mitm` 里按 canonicalize 格式（path+query+xy_platform_info）
   还原出输入，要么重新 Frida 抓包时 hook libxyass + 0x23e54 入口
   直接 dump 入参。没有这个，任何静态算法假设都没法 sanity-check。

**本轮的 static-only 天花板**：我在 `intercept()` 上做了完整的 capstone
反汇编 + CFG 扫描 + helper 跟踪 + 递归 crypto 常量搜索（1032 条 thumb 指令
+ 85 个后代函数），找到的事实是 "crypto 不在表面" 但**没有发现任何能让
纯 Py 复写一步到位的捷径**。下一步必须从 `0xdff0` 解密函数开始顺藤摸瓜。

## libxyass 解密函数深挖（第二轮 Ghidra + capstone）

### 9 个解密函数的坐标（来自先前会话 + 本轮确认）

```
0x1a170  0x1bc30  0x1ddac  0x1d580  0x1b29c  0x1e560  0x1cc6c  0x1a9fc  0x1c440
```

本轮用 capstone profile 了 9 个函数的指令特征，所有 9 个共享一个签名：

| fn | bytes | insts | mov_pc | bl | blx | ldr[pc,] | movw |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0x1a170 | 1850 | 607 | **39** | 0 | 0 | 34 | 69 |
| 0x1bc30 | 1772 | 612 | 39 | 0 | 0 | 35 | 70 |
| 0x1ddac | 1178 | 410 | 27 | 0 | 0 | 26 | 40 |
| **0x1d580** | **200** | **65** | **3** | 0 | 0 | 4 | 8 |
| 0x1b29c | 1644 | 525 | 31 | 0 | 0 | 29 | 73 |
| 0x1e560 |  432 | 143 | 7 | 0 | 0 | 9 | 16 |
| 0x1cc6c | 1192 | 383 | 21 | 0 | 0 | 22 | 56 |
| 0x1a9fc |  712 | 228 | 11 | 0 | 0 | 13 | 27 |
| 0x1c440 |  674 | 215 | 12 | 0 | 0 | 12 | 26 |

**共同特征**：零 `bl`/`blx`（完全自包含，不调外部函数）+ 大量 `mov pc, rN`
CFG flatten + 大量 `movw`/`movt` 构造 32-bit 立即数。所有 key material 都在
函数自己的 literal pool + 传入参数里。

### 误报 1：`0xdff0` / `0xe0c8` 不是解密函数

之前怀疑这两个是字符串解密入口，本轮反编译后确认：

- `0xdff0`: 保存栈 canary → `dmb ish`（内存栅栏）→ 检查初始化标志位
  → 调用 `bl #0xe19c` → 返回。**这是 C++ Itanium ABI 的 `__cxa_guard_acquire`**
- `0xe0c8`: 对称的 `__cxa_guard_release`
- `0xd7a4`/`0xd7f0`: `xmalloc` 及其 tail-call 别名
- `0xd9a8`: libc++ `basic_string::assign` 的 small-string 内联拷贝

**这些全是 C++ 标准库辅助函数**，被大量静态局部对象的 once-init 逻辑调用。
和 shield 逆向无关。

### 0x1d580 的核心算法片段（手工追出来的 XOR 循环）

200 字节 / 65 条 thumb 指令，只有 3 个 `mov pc, rN`，是 9 个里最小的。
从反汇编里能直接看到核心字节处理循环（0x1d610..0x1d624）：

```text
0x1d604  ldr    r0, [r7, #-0x44]   ; r0 = input_ptr (saved local)
0x1d60c  ldrb   r0, [r0]           ; r0 = input_byte
0x1d610  ldrb   r1, [r7, #-0x4d]   ; r1 = key_byte (stack-local, iter-updated)
0x1d61c  eors   r0, r1             ; r0 ^= r1    ← XOR
0x1d622  mvns   r0, r0             ; r0 = ~r0    ← NOT
0x1d624  strb   r0, [r5]           ; *output++ = r0  ← store
```

核心操作就是 **`out_byte = ~(in_byte ^ key_byte)`**。key_byte 的生成在
CFG flatten 扯到别处的基本块里。

### 误报 2：`__stack_chk_guard` 不是加密状态

0x1d580 prologue 里 `ldr r0, [pc, #0x3b4]` → PC-rel base = 0x7dad8。
解析 .rel.dyn 后看到：

```
VA 0x7dad8  type=GLOB_DAT  sym=#19 '__stack_chk_guard'  addend=0x0
```

所以 r6/canary 访问就是**标准 stack-protector 序言/尾声**，和加密算法无关。
之前在这里追了半天全是噪声。

### 真正的 CFG flatten 机制（本轮终于看清了）

0x1d580 的第一个 `mov pc, r1` 在 0x1d5f6。向上追 r1 的 def chain：

```text
0x1d598  ldr r2, [pc,#0x3b0]        ; lit@0x1d94c = 0x0005e744
0x1d5a8  add r2, pc                 ; r2 = pc_at_0x1d5ac + 0x5e744 = 0x7bcf0
0x1d5be  ldr r0, [r2, #0x10]        ; r0 = *(0x7bd00)
0x1d5d6  movw r1, #0x43c0
0x1d5da  movt r1, #0xfc1c            ; r1 = 0xfc1c43c0 (signed -0x3e3bc40)
0x1d5e0  add r1, r0                 ; r1 = r0 + 0xfc1c43c0
0x1d5f6  mov pc, r1                  ; *** JUMP ***
```

`r2 = 0x7bcf0` 落在 `.data` 区。对应的 `.rel.dyn` 条目：

```
VA 0x7bcf0  type=RELATIVE  addend=0x03aecd20
VA 0x7bcf4              =0x03555b9c
VA 0x7bcf8              =0x03318692
VA 0x7bcfc              =0x03e57acc
VA 0x7bd00              =0x03e59510   ← r2[+0x10]
VA 0x7bd04              =0x030cf7ca
VA 0x7bd08              =0x03dcd712
VA 0x7bd0c              =0x03163b7c
...（继续到 0x7bd34，共 60+ 条）
```

**R_ARM_RELATIVE 语义**：加载时 `*slot = load_base + addend`。库本身从
vaddr=0 加载，所以实际上 `*slot = addend`（加载后 r2[+0x10] = 0x03e59510）。

然后：
```
r1 = 0x03e59510 + 0xfc1c43c0 = 0x00005d8d0 & 0xffffffff = 0x5d8d0
```

**`0x5d8d0` 是一个合法 .text VA**！我顺着反汇编过去验证了：

```text
0x5d8d0  lsls     r0, r5, #8
0x5d8d2  movt     r2, #0x367
...
0x5d8de  ldr.w    r0, [r0, #0x298]   ; 读某个 struct field
0x5d8ee  ldr.w    r1, [r6, #0x1dc]   ; 从 r6 指向的大结构体
0x5d8f2  str.w    r1, [r6, #0x210]   ; 搬到另一个 slot
0x5d8f6  ldr.w    r1, [r6, #0x1d0]   ; ← 这块是 "permutation" 阶段
0x5d8fa  str.w    r1, [r6, #0x224]   ;   把 r6 指向的 ~16 个字段重排位置
...（共 ~20 条 ldr/str pairs）
```

落地是合法代码。**CFG flatten 的确是可以静态解的**——每个 `mov pc, rN`
目标都能通过 `reloc_addend[slot] + inline_constant` 算出来。

### 纯 Py 复写 0x1d580 的可行路径（工程化方案）

1. 解析 .rel.dyn 构造 `slot_addend[]`（已经验证 60+ entries 里我们需要的
   r2+0x10、r2+0x14、r2+0x18 全部有 RELATIVE 重定位）
2. 对每个 `mov pc, rN` 指令，追 rN 的 def chain 到 `add rN, rX, constK`
   形式，其中 `rX` 是一个 `ldr rX, [r2, #offset]`，计算
   `target = slot_addend[r2+off] + constK`
3. 递归反汇编每个 target 块直到遇到 `pop {pc}` 或 `bx lr`
4. 把所有块按执行顺序串起来，得到真正的线性字节流
5. 对线性流做 data flow 分析，识别：
   - 输入参数流转（input_ptr、input_len）
   - key_byte 来源（stack local 更新模式）
   - 输出 `*r5 = out_byte` 的指针维护
6. 把线性体转写成 Python

**工作量估算**：0x1d580 (3 flatten) ≈ 1 小时；0x1d9a8 / 0x1c440 (11-12 flatten) ≈ 2-3 小时；
大的 0x1a170 / 0x1bc30 (39 flatten) ≈ 4-6 小时每个。9 个全部做完约 2-3 人日。

### 本轮提交到项目的 Ghidra 产物

- [scratch/ghidra_work/DecompileHelpers.java](../scratch/ghidra_work/DecompileHelpers.java) — 对指定地址列表强制设 Thumb mode + disasm + decompile
- [scratch/ghidra_work/ResolveNativeMethods.java](../scratch/ghidra_work/ResolveNativeMethods.java) — 追 RegisterNatives 的 methods 参数
- [scratch/ghidra_work/DumpJniOnLoad.java](../scratch/ghidra_work/DumpJniOnLoad.java) — 反编译 JNI_OnLoad + 扫 JNINativeMethod
- [scratch/ghidra_work/disasm_1d580.txt](../scratch/ghidra_work/disasm_1d580.txt) — 83 条指令的完整反汇编 + PC-rel 字面量解析

下一轮直接从"用静态重定位表 + inline 立即数算出所有 9 个解密器的完整 CFG"开始。

## libxyass 解密函数深挖（第三轮：CFG flatten resolver + 执行验证）

### 成果总览

1. **[cfg_flatten_resolver.py](../scratch/ghidra_work/cfg_flatten_resolver.py)**：
   静态展开任意解密函数的 CFG flatten。在 0x1d580 上成功追了 6 个基本块 / 79 条指令，直到击中一个数据驱动的循环（`add r8, r1` 让 r8 每次迭代漂移→下一个 `mov pc, rN` 目标也漂移）
2. **[decrypt_runner.py](../scratch/ghidra_work/decrypt_runner.py)**：
   无 Android、无 JNI 的独立 Unicorn harness，仅把 libxyass 原始字节 map 进内存就能执行 9 个解密器中任一个。对 0x1e560 + 42 字节真实输入执行 **17170 条指令、648 唯一 PC、无任何 unmapped 访问**——**证明解密函数完全 self-contained**（0 个 bl/blx 到外部 + 静态分析+执行验证双重确认）

### 关键技术发现

#### 1. Thumb PC 语义的两条不同规则

纯静态 resolver 卡在第二个 CFG flatten target 算到 0x1d9a6（奇偶不对）时，用 Unicorn 抓了一个 50 条指令的 trace 发现：

```text
0x1d5de  add r3, pc       → r3 becomes 0x1d9a8 (not 0x1d9a6)
```

即：**`add Rdn, PC` 使用 `(inst_addr + 4)`，不做 4 字节对齐**。
而 `ldr rD, [pc, #imm]` 使用 `Align(inst_addr + 4, 4)`。

这个差异在 ArmARM 里不显眼，但在被严重滥用 PC 算术的混淆代码里每两字节错一次。Unicorn/Capstone/真机都一致实现 unaligned 的 `add-with-pc`。

修了这一条后 resolver 能连续解 5 个 flatten（原来只解 1 个）。

#### 2. .rel.dyn 的 R_ARM_RELATIVE 条目充当 CFG flatten 的跳转表

解密函数里每个 `mov pc, rN` 的跳转目标都是：

```
target = slot_addend[.rel.dyn entry for (r2 + offset)] + inline_const_from_movw_movt
```

`.rel.dyn` 里有 **2696 条** R_ARM_RELATIVE 条目，`r2 = 0x7bcf0` 周围的 60+ 条都是这些 flatten 的跳转槽。加载时 `*slot = load_base + addend`；加载基为 0，因此 `*slot = addend` 可纯静态读取。

`cfg_flatten_resolver.py` 里 `load_relocations()` 把这些全部提前加载成 `{slot_va: addend}` 字典，然后 def-use 反向追踪每个 `mov pc` 需要的寄存器即可算出目标。

#### 3. 解密函数是 "data-driven control flow"

追到第 6 个 block 后，resolver 检测到 loop-back：从 0x1d77e 尾部的 mov pc 又回到了 0x1d8b8。同时 0x1d8b8 内部有 `add r8, r1` 修改 r8——这让下一次 `mov pc, r0 = 0xfcbe7534 + r8` 的目标每次迭代不同。

**静态 resolver 无法展开这种循环**（每次迭代的寄存器快照不同），但可以：
- 证明函数是纯本地运算（由 `resolver → 检测不到 bl/blx/unmapped-ldr` 确认）
- 证明所需的全部外部数据仅是输入缓冲 + `.data` 重定位表
- 因此一个最小的 Unicorn 内存模型就能执行它

#### 4. Unicorn 作为"静态评估器"的合理性

```python
uc.mem_map(0, 0x100000)                 # 全部第一 PT_LOAD
uc.mem_write(0, data[:0x76900])          # libxyass 自己的字节
uc.mem_write(0x7a900, data[0x76900:...]) # 第二 PT_LOAD
uc.mem_map(STACK_BASE, STACK_SIZE)       # 栈
uc.reg_write(R0, input_ptr)              # r0 = 输入指针
uc.reg_write(R1, input_len)              # r1 = 输入长度
uc.emu_start(fn_va | 1, ...)
```

就是这么多。没有 Android、没有 JNI、没有 ioctl、没有 libc。**任何对真机的依赖 = 0**。decrypt_runner.py 对 0x1d580 和 0x1e560 都跑通（前者 6199 条指令，后者 17170 条指令），完成后取 INBUF 的内容就是 in-place 解密结果。

### 本轮**证否**的假设

- ❌ **`0xa000..0xa02a` 是加密字符串**（先前 `all_decrypted_strings.json` 的假设）。本轮读该区域发现内容是 ASCII `GLOBAL__N_116itanium_demangle10MemberExprE`——**明文 C++ demangle 符号**，根本没加密。之前脚本把它送去 decrypt 0x1e560 得到看起来像密文的垃圾，被误判为"解密成功但乱码"。
- ❌ **9 个解密函数需要初始化状态才能运行**。本轮单独运行 0x1e560 执行了 17170 条指令无任何 unmapped 访问、无外部调用，证明它们 **完全 self-contained**：所有必要数据都在 .rodata / .data / 栈里，输入缓冲就是唯一的 runtime 参数。

### 仍然未解的 blocker（下一步具体目标）

**真正的加密 blob 在哪里？**
不在 0xa000。要找到真正的加密字符串数据块需要：

1. 在 libxyass 里定位所有调用解密函数的点（已知调用者：intercept@0x23e54 调 13 个直接 bl 目标，部分是解密函数；JNI_OnLoad 也调用解密函数）
2. 对每个调用点，静态追出 r0（输入指针参数）的来源——通常是一段 copy from `.data.rel.ro` 或 `.rodata` 的 ciphertext
3. 用 decrypt_runner 对这些 blob 跑对应的解密函数，输出明文

这一步是纯静态 + Unicorn 的组合任务，**不需要真机**。

### 完成这一步后能得到什么

一旦所有 ciphertext blob 都能离线解密：
- 看到 `Native.intercept` 注册到的真实 JNI 方法名（目前被加密隐藏）
- 看到 `intercept()` 里所有字符串字面量（"shield", "xy-platform-info", "canonicalize" 等）
- 看到 shield canonicalize 的字符串模板（应该会出现 "platform=android&build=%d&deviceId=%s" 这种）
- 看到 shield inner hash 调用的函数名（MD5/SHA1/HMAC 以及 key material）

那之后，shield 签名就彻底纯 Py 化——不再需要任何 emulation，只需要一次性把所有字面量解出来烘焙成 Python 常量表。

## libxyass 字符串解密端到端成功（第四轮）

### 🎯 突破性结果

本轮把前三轮的 CFG flatten resolver + decrypt runner 和**新写的 ciphertext 提取器**串成一条完整流水线，在 libxyass 里**不接真机**完整地解出了 4 个真实字符串：

| caller | decrypt fn | size | ciphertext | **plaintext** |
|---|---|---:|---|---|
| `0x242e6` | `0x1a170` | 4 | `2e510300` | **`"xy-"`** |
| `0x2490a` | `0x1d580` | 17 | `331a04e0b1fd5cc8db4ebab0b473990db4` | **`"xy-platform-info"`** 🎯 |
| `0x253c8` | `0x1c440` | 2 | `7bab` | **`"s"`** |
| `0x2540c` | `0x1bc30` | 31 | `028145e6d27c4e823a43b3bdd08d2342ec776e380e8349ca40775bd4b793` | **`"closing the old response error"`** |

**`xy-platform-info` —— 这就是 shield 签名链里那个关键 HTTP 头名字**。它从 libxyass 的 .rodata 密文里被纯静态解出来了，和之前从抓包里看到的真机字符串完全一致。这证明：
1. 我们的 CFG flatten 理论正确（Thumb PC 语义修对了之后）
2. 我们的 Unicorn decrypt 执行器正确（无需任何 Android runtime）
3. 密文提取器的 Pattern A（movw/movt/str 立即数堆叠）和 Pattern B（`ldr [pc,#X]` + `add r0,pc` + `vld1.8` 从 .rodata）都工作
4. `0x1d580` 确实是一个字符串解密函数

### 技术要点

#### 1. 线性反汇编有缺陷，BL 编码直扫才找到真 caller

Capstone 线性反汇编 libxyass .text 时会把嵌在代码中的 literal pool / padding 字节误解成 NEON 协处理器指令（`stc2l p15, c15, ...` 等）然后"吞掉"后面的 BL 指令。这就是为什么第一版 scan_decrypt_calls 只找到 0 个 caller。

修复：**直接用 Thumb-2 BL 编码字节模式匹配**（`hw1 & 0xF800 == 0xF000` 且 `hw2 & 0xD000 == 0xD000`）对 .text 作 2 字节步进全扫，独立解码每个命中的目标地址。这样绕过线性反汇编的对齐错误。结果：.text 共 1475 个 BL 指令，238 个不同的目标函数。

#### 2. 密文提取的两个静态模式

**Pattern A — immediate 堆叠**（用于 ≤4 字节短密文）：
```asm
movs  r0, #N            ; N = size
bl    xmalloc
mov   tmp, r0
movw  r0, #LO           ; 低 16 位密文
movt  r0, #HI           ; 高 16 位密文
str   r0, [tmp]          ; 写入堆buffer
mov   r0, tmp
movs  r1, #N
bl    decrypt_fn
```
密文就是 `(HI << 16) | LO` 拼出来的 32 位立即数。对 size=2 用 `strh`，size=1 用 `strb`。

**Pattern B — .rodata PC-relative 拷贝**（用于较长密文）：
```asm
ldr   r0, [pc, #X]      ; X = literal pool offset
add   r0, pc            ; r0 = ciphertext source VA
vld1.8 {d16,d17}, [r0]! ; 批量 load 16B
vst1.8 {d16,d17}, [dst]!; 批量 copy 到 heap
... (重复或补足 size % 16)
mov   r0, dst
movs  r1, #N
bl    decrypt_fn
```
源地址 = `literal_at(pc_at_ldr+imm) + pc_at_add_unaligned`。

#### 3. decrypted_strings_v3.json

4 个 blob 和明文已保存至
[scratch/ghidra_work/decrypted_strings_v3.json](../scratch/ghidra_work/decrypted_strings_v3.json)。

### 本轮新增文件

- [scratch/ghidra_work/scan_decrypt_calls.py](../scratch/ghidra_work/scan_decrypt_calls.py) — Thumb BL 编码扫描器 + Pattern A/B 密文提取器
- [scratch/ghidra_work/encrypted_blobs.json](../scratch/ghidra_work/encrypted_blobs.json) — 提取到的 4 个密文
- [scratch/ghidra_work/decrypted_strings_v3.json](../scratch/ghidra_work/decrypted_strings_v3.json) — 4 个已解密的明文字符串
- [scratch/ghidra_work/find_encrypted_blobs.py](../scratch/ghidra_work/find_encrypted_blobs.py) — 前期版本（被 scan_decrypt_calls 取代）

### 证伪：9 个"解密函数"只有 4 个是真解密器

先前会话把 `0x1a170, 0x1bc30, 0x1ddac, 0x1d580, 0x1b29c, 0x1e560, 0x1cc6c, 0x1a9fc, 0x1c440` 统统标为"解密函数"，因为它们有相同的指令特征签名（零 bl/blx + 大量 mov pc + movw）。

但本轮全量 BL 扫描显示**只有 4 个真被直接调用**：`0x1a170, 0x1bc30, 0x1c440, 0x1d580`（每个恰好 1 次）。另外 5 个（`0x1ddac, 0x1b29c, 0x1e560, 0x1cc6c, 0x1a9fc`）在整个 .text 里**零直接 caller**。

两种可能：
- 它们其实不是解密函数，只是和解密函数有相同的 CFG flatten 结构
- 它们是通过 `mov pc, rN` 计算跳转间接进入的（不是直接 BL）

鉴于 `__cxa_guard_acquire` (0xdff0) 有 **109 个 caller**（每个都是一个静态局部的 lazy init 包装器），绝大多数字符串解密应该是通过这条路径进行的：
`bl __cxa_guard_acquire → init_fn → (CFG flatten) → decrypt_fn`

这条路径上的 decrypt 调用被 `mov pc, rN` 隐藏，不能简单 BL 扫描命中。要展开它们需要对每个 `bl 0xdff0` 调用点的 init_fn 做 CFG flatten 追踪，直到撞上一个写 r0/r1 后指向 decrypt 函数入口的 `mov pc`。

这是下一轮的具体工作。

### 仍然未解的问题（第四轮后更新）

本轮深度验证后**修正了"只解出 4 个字符串不够"的判断**：

#### libxyass 的字符串表就是 4 个——这是全部

花了多种方式交叉验证：

1. **全 .text BL 扫**（1475 个 BL，238 个唯一目标）：只有 `0x1a170, 0x1bc30, 0x1c440, 0x1d580` 是被 BL 调用的 decrypt fn，每个 1 次 = 4 次总直接调用
2. **扩展候选列表**（从性能分析挖了另外 4 个可疑函数 `0x1a442, 0x1ac40, 0x1c4e4, 0x1dc1a`）：再扫一轮，发现前 3 个实际上是 confirmed decrypt fn **内部的子块**，`0x1dc1a` 是独立函数但其调用点提取不到 Pattern A/B
3. **__cxa_guard wrapper 静态枚举 + 模拟执行**：109 个 guard site，属于 10 个 wrapper 函数；对这 10 个 wrapper 用 stub 过的 Unicorn 各自从入口执行，**零 decrypt hit**。说明这些 wrapper 不走 decrypt 路径
4. **扫 movw/movt 对产生 decrypt fn 地址的地方**：0 个命中
5. **扫 .data/.data.rel.ro/.bss 的函数指针表**：0 个 decrypt fn 指针
6. **B.W 无条件分支到 decrypt fn**：0 个命中
7. **间接 blx 指向 pc-rel 加载的 decrypt fn 地址**：0 个命中

**结论**：libxyass 只有 4 个加密字符串，全部通过直接 BL 解密：`"xy-"`, `"xy-platform-info"`, `"s"`, `"closing the old response error"`。不存在别的藏起来的字符串。

#### 架构含义

libxyass 原来设计得很精简：
- **运行时字符串需求极少**：签名过程只需要几个 header 名字（`xy-platform-info`）+ debug 字符串
- **其他字面量都在别处**：
  - Java 侧（`ux8/a0.java` 剥光列表显示 Java 知道 `shield`, `x-mini-*` 等头名字）
  - libtiny 侧（`x-mini-*` 是 libtiny 注入的）
  - .rodata 里的 plaintext C++ 符号（ABI 要求，不加密）
- **crypto 操作不查字符串**：shield 的 inner hash 不是由 `"HMAC-SHA1"` 这种字符串查表触发的，而是一段直接的数值运算

所以如果要找 shield inner hash 算法，**静态字符串搜索已经榨干**，下一步必须反汇编 intercept() 的字节流寻找算术模式（SHA 的 round 常量、MD5 的 T 表、HMAC 的 ipad/opad 常量等）。我们第二轮试过，0 个命中——意味着 inner hash 也许是**自研算法或 XOR 混淆过的标准 hash**。

#### 下一轮具体目标

1. **用 Unicorn stub 模式运行 intercept()**：给它一个 fake JNIEnv + 假 request，观察 shield 生成过程中的内存写入，直接抓 canonicalize → shield_tail 的转换
2. **或**：把 intercept() 里的所有 **blx rN** 间接调用做 def-use 追踪，找出哪个是 inner hash（可能是通过 C++ vtable 分派）
3. **或**：对 intercept 调用的 helper `0x1ee70`（1552 字节，从 intercept prologue 调用）做 CFG 追踪——它可能是 canonicalize builder

4 个字符串的成果已经让我们拿到了**纯静态 RE 的第一块 ground truth**，下一步是把这条路径扩展到更复杂的签名操作。

## libxyass shield 的 crypto primitives 全部静态定位（第五轮）

### 🎯 关键发现：shield 使用 HMAC-MD5 + base64

通过在 libxyass 的**全段字节**（.text + .rodata + .data）里扫描标准 crypto 常量，而不是像前几轮只扫 .text 的立即数，一次性挖出了 shield 的**完整 crypto 基础设施**：

| 常量 | 位置 | 含义 |
|---|---|---|
| **MD5 T[0..63] 完整 64 项表** | file `0x79418` / VA `0x7d418` (.data) | libxyass 内置的 MD5 实现 |
| **MD5 init state h0..h3** | file `0x2ad60` (.text literal pool) | 第二个 MD5 实例的初始状态 |
| **MD5 init state h0..h3** | file `0x6f1d0` (.text literal pool) | MD5 core 0x6f010 的 literal pool |
| **HMAC ipad `0x36363636`** | file `0xb514` (.rodata) | HMAC 外层 key-XOR 常量 |
| **HMAC opad byte `0x5c`** | file `0x2ad74` (.text literal pool) | HMAC 外层 key-XOR 常量 |
| **Base64 字母表 ×4 副本** | file `0xb52c, 0xb56c, 0xb5ac, 0xb5ec` (.rodata) | SIMD-friendly base64 编码器 |

**结论**：shield 的内层 hash **是 HMAC-MD5**（不是 HMAC-SHA1，不是 MD5，不是 custom hash）。前几轮验证 HMAC-SHA1 失败是因为**猜错了算法**。base64 的 4 份字母表副本确认了输出做 base64，和抓包里 shield 是 base64 字符串一致。

### 📞 Shield 生成调用链

从 xref 分析还原出 shield 从 intercept 到最终 base64 输出的完整路径：

```
XhsHttpInterceptor.intercept (Java)
  └─→ libxyass Native.intercept @ 0x23e54
        ├─→ [vtable 间接调用] 0x24bcc  (shield builder — 0 个直接 BL caller，说明走 C++ vtable)
        │     ├─→ bl 0x2ad80  (HMAC-MD5 wrapper — 有 MD5 h0..h3, 0x5c opad, -64 block size 的 literal pool)
        │     │     └─→ MD5 内部使用 0x79418 的 T 表 (Tab 0..63) 做 round 运算
        │     └─→ ... (其它 shield 拼装步骤)
        └─→ bl 0x286d0 @ 0x24aa0  (Base64 encoder — 使用 0xb52c 的字母表)
              └─→ 输出 100 字节 shield 的 base64 形式
```

**关键数据点**：
- `0x24bcc` 在 intercept 主体（0x23e54..0x248ce）**之后**约 0x400 字节
- `0x24bcc` 有 **0 个直接 BL caller**—— 通过 C++ 虚表分派，intercept 里的某个 `blx rN` 命中它
- `0x2ad80` 的唯一 BL caller 就是 0x24cfa（在 0x24bcc 内部）
- `0x286d0` 的唯一 BL caller 就是 0x24aa0（在 intercept 内部，靠近尾部）

### 🧪 HMAC-MD5 假设测试

拿到"shield 使用 HMAC-MD5"的明确答案后，对 **已知的 canonicalize + shield_tail + DEVICE_MASK 样本**做了快速假设验证：

```python
canon = b'/api/model_portrait/detect_itemscpu_name=Pixel%206platform=android&build=9190807&deviceId=aa293284-0e77-319d-9710-5b6b0a03bd9c'
shield_tail = bytes.fromhex('77e6a94e65fb91154d6a14ba7251e2f1')
device_mask = bytes.fromhex('95d17cdfa2bb91e9947b3b485623f7bb')
target = bytes(a^b for a,b in zip(shield_tail, device_mask))
# target = e237d591c74000fcd9112ff22472154a  (what HMAC-MD5 should produce)
```

朴素尝试全部未命中：

| 假设 | 输出 | 命中 |
|---|---|---|
| `MD5(canon)` | `466125d3...777e` | ❌ |
| `HMAC-MD5(b'9190807', canon)` | `c4a0a2be...d8d0` | ❌ |
| `HMAC-MD5(device_mask, canon)` | `a0cbe89d...0c1a` | ❌ |
| `HMAC-MD5(deviceId_utf8, canon)` | `f2435d65...79f0` | ❌ |
| `HMAC-MD5(deviceId_bytes16, canon)` | `e17ebbbf...9d83` | ❌ |
| `HMAC-MD5(b'', canon)` | `34036ebd...dd9d` | ❌ |
| `MD5(key ‖ canon)` 多种 key | 全部 | ❌ |
| `MD5(canon ‖ key)` 多种 key | 全部 | ❌ |

**这意味着**：
- 算法已知（HMAC-MD5）✓
- 消息**可能不是** `canonicalize` 原文——可能多了前缀/后缀/长度编码/URL encoding 变体
- key **不是**任何显然的常量——可能是运行时从某个状态派生（cert hash、deviceId 的某个哈希、或从一个 .bss 全局取）
- 或者 canonicalize 样本本身是污染的（上一轮 Frida 抓取过的 ctx_pre 已经证明抓点错了）

### 下一步具体目标

上一轮的 blocker 是"不知道是什么 hash"，本轮已经解决：**是 HMAC-MD5**。现在的 blocker 转成"key 和 message 是什么"。三条可行路径：

1. **Unicorn 模拟 `0x24bcc` 或 `0x2ad80`**，喂进伪造的 canonicalize + 标准 device 状态，观察它把 HMAC 的 key 和 message 写到哪里、用什么值。Unicorn 的内存 hook 一发即可抓出 key/msg。
2. **静态反编译 `0x24bcc` 的序言**——看它怎么把 canonicalize 指针和 key 指针准备好再调 `bl 0x2ad80`。寄存器追踪配合 .data 的 xref 能拿到 key 的来源。
3. **扩大 canonicalize 变体测试集**——继续枚举 URL encoding 变体、加前缀/后缀、不同字段顺序等，同时用从抓包里取得的**多个** (canon, shield) 样本做同时匹配（一个正确的 key 必须在所有样本上都匹配）。

### 本轮新增的关键事实（写入项目）

- libxyass 有 **1 个 MD5 T 表** + **2 个 MD5 init state 副本** + **1 个 HMAC ipad 常量** + **HMAC opad byte 单独嵌入 literal pool** + **4 份 base64 字母表（SIMD 快解码拷贝）**
- shield 的 base64 编码器在 `0x286d0`，intercept 里唯一的调用点在 `0x24aa0`
- shield 的 inner hash 是 HMAC-MD5，实现在 `0x2ad80`，唯一的调用点在函数 `0x24bcc` 的内部 `0x24cfa`
- `0x24bcc` 是 shield 的主 builder，通过 C++ vtable 被 intercept 间接调用（0 个直接 BL）

## Unicorn 模拟 shield builder 尝试（第六轮）

### 📝 进展

写了 [scratch/ghidra_work/run_intercept_v2.py](../scratch/ghidra_work/run_intercept_v2.py)：
- 加载 libxyass 字节
- 启用 NEON/VFP（`CPACR + FPEXC`）让 `vmov.i32 q8, #0` 等指令可执行
- Stub 掉 `xmalloc / __cxa_guard_acquire / __cxa_guard_release`
- 假造 JNIEnv vtable（256 个 slot 指向 trampoline 区，每个 hook 拦截）
- Hook 监视 `0x24bcc`（shield builder）/ `0x2ad80`（HMAC-MD5）/ `0x286d0`（base64）进入时的寄存器 + 缓冲区
- 捕获最后 15 条指令的 trace 供崩溃分析

### 结果：第 59 条指令崩溃

```
ENTER SHIELD_BUILDER @ 0x24bcc  r0=0x50000000 r1=0x50000100
...执行 59 条指令后...
Invalid instruction @ pc=0x1e
Last 15 PCs: 0x1ee06..0x1ee18, then PC=0x6, 0xa, 0xe, 0x12, 0x16, 0x1a, 0x1e
```

**分析**：
- 0x24bcc 的入口代码从 fake_chain（0x50000000）读取 struct 字段
- 经过几十条初始化指令后，在 helper 0x1ee06 里进入一个虚函数分派
- 那个虚表指针（应该是 chain→vtable→method）在我们的 fake object 里是 **0**
- 导致 `blx r3` 跳到 `pc = 0 | 1 = 1` → 执行 ELF 文件头字节 `\x7f E L F ...`
- 这些字节被 ARM Thumb 错误解码，最终在 0x1e 处遇到无效指令

**根因**：fake Chain/Request 对象没有 C++ vtable。要让 shield_builder 真正跑起来需要：
1. 分析 0x24bcc 对 chain 结构的访问模式（哪些字段、哪些 vtable method）
2. 为每个访问的字段提供合理的 fake 值
3. 为每个 vtable method 提供 stub 实现（返回假字符串/数字）

这是具体但耗时的工作，需要把 C++ object graph 完整 stub 出来。

### 下轮起点

下一轮直接继续扩展 `run_intercept_v2.py` 的 fake object graph：

1. 先反汇编 0x24bcc 的完整 prologue（约 80 条指令到第一个 mov pc），看它读 `chain+0x0 / chain+0x4 / chain+0x8 / chain+0xc / ...` 每个 offset 是什么
2. 对每个需要的 offset 填假值或假指针
3. 对每个需要的虚函数 slot 填 trampoline
4. 继续推进执行，直到 PC 进入 0x2ad80 为止

一旦 PC 到达 0x2ad80，我们就能通过 r0/r1/r2/r3 直接观察 HMAC-MD5 的 key 和 message——**这是锁定 shield 算法最快的路径**。

### 本轮的额外假设测试（多样本）

本轮还对 **342 个 session2 请求**的 shield_tail 做了统计验证：

- 抓了 5 个 note API 请求，计算 `target = shield_tail XOR DEVICE_MASK`
- 所有 5 个 target 首字节都落在 0xe3..0xe8 范围——前 4 位非随机
- 对每个 target 测试 20+ 个 HMAC-MD5 / plain MD5 变体：**全部未命中**

这佐证了 **key/msg 构造是非平凡的**，不是 canonicalize/HMAC-MD5 的直接调用。很可能 message 在送入 HMAC 之前做了某种预处理（长度编码、前缀、CRC 等）。

### 本轮新增文件

- [scratch/ghidra_work/run_intercept_v2.py](../scratch/ghidra_work/run_intercept_v2.py) — Unicorn shield builder harness with watchpoints, JNIEnv stubs, crash trace

## 第七轮：SHA-1 不是 MD5（关键纠正）+ shield 布局修正

### 🎯 关键纠正

**纠正一：算法是 SHA-1 而不是 HMAC-MD5**

之前在 .data 里发现 MD5 T 表以为找到了 inner hash，但那是另一个不相关子系统用的。真正的 shield inner hash 算法通过 **直接 Unicorn emulate** 0x2acb0 确认：

```
ctx after INIT = 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 f0 e1 d2 c3 ...
               = h0           h1          h2          h3          h4
               = SHA-1 初始状态 (h4 = 0xc3d2e1f0, MD5 没有 h4)
```

**`0xc3d2e1f0` 是 SHA-1 独有的 h4**——这是一锤定音的证据。MD5 只有 4 个 H 值（16 字节），SHA-1 有 5 个（20 字节）。

函数锁定：

| 函数 | 入口 | 作用 |
|---|---|---|
| `sha1_init(ctx)` | `0x2acb0` | 写入 `h0..h4` 到 ctx，读取 0x2ad60 的 h 常量 |
| `sha1_update(ctx, msg, len)` | `0x2ad80` | 吸收输入字节，更新 bit counter |
| `sha1_final(ctx, out)` | `0x2b27c` | 填充 + 最终压缩 + 输出 digest |

**验证**：对 `"hello world"` (11 字节) 调用 init+update 后，ctx 的 bit counter 字段 = `58 00 00 00` = 88 bits = 11 × 8 ✓

**纠正二：shield layout 是 85 + 15 而不是 84 + 16**

从 session2 的 **329 个唯一 shield 样本**做逐字节熵分析：

```
位置 80-83: 每个位置 1 个唯一字节 → prefix (device-constant)
位置 84:    16 个唯一字节, ALL upper nibble = 0x7 → prefix 的结构字节
位置 85-99: 每个位置 180+ 个唯一字节 → hash 输出（random）
```

shield 的实际结构：

```
shield (100 bytes):
  [0..85)  = device prefix (85B, 完全 device-constant)
  [85..100) = hash XOR device_mask (15B)
```

**device_mask 从 16 字节改成 15 字节**：`d17cdfa2bb91e9947b3b485623f7bb`（去掉原 16 字节版本的首字节 `95`）。

### ❌ 为什么 HMAC-MD5 假设全部失败

因为它根本就不是 MD5——是 SHA-1。前几轮 verify_hmac_sha1_hypothesis.py 失败是因为 ctx_pre 数据污染 + layout 错误。

### 本轮 Unicorn 运行结果

[scratch/ghidra_work/run_hmac_md5.py](../scratch/ghidra_work/run_hmac_md5.py) （注：文件名保留历史记录，实际实现是 SHA-1）：

- ✅ `sha1_init` emulate 成功，ctx 得到正确的 h0..h4
- ✅ `sha1_update` 对 "hello world" 后 bit counter = 88 bits ✓
- ⚠️ `sha1_final` 运行时写出 padding byte `0x80` 和 bit count `0x18`，但最终 H 状态没回写到 ctx[0..20] 或 r1 输出缓冲——CFG flatten 可能走歪或者 digest 写到我没读的位置

### 下一轮的明确路径

1. **定位 sha1_final 输出位置**：用 `UC_HOOK_MEM_WRITE` 全量 hook 0x2b27c 的每个字节写入，搜索 SHA-1 digest 出现的地址
2. **一旦 digest 可读，确认是标准 SHA-1**：对比 `hashlib.sha1("abc").digest()`
3. **确认后，用 Python 的 `hashlib.sha1` 做假设测试**：基于 15B layout + 更宽的 key/canon 组合搜索，可能包括 HMAC(HMAC(canon, k1), k2) 双层构造

## 第八轮：广谱 SHA-1/HMAC-SHA1 假设测试全军覆没

### 测试矩阵

基于第七轮的纠正（算法=SHA-1，layout=85+15），本轮对 **真实 session2 抓包数据**做广谱验证：

- **已知 canonicalize 样本**：`/api/model_portrait/detect_items` 请求 (canon = `path + query + xpi`, 126 字节) —— 本 session 恰好发了一次这个 endpoint 的请求
- **测试方式**：对真实 15-byte tail 做 `XOR device_mask` 得到 target_hash，然后枚举大量 `(canon_formula, key, slice_offset)` 组合求 `SHA-1(canon)[s:s+15]` 或 `HMAC-SHA1(key, canon)[s:s+15]` 是否命中

### 测试规模

| 维度 | 候选数 |
|---|---|
| canonicalize 公式 | 14 (p+q, p+q+xpi, p+q+xcp, p+body, M+p+q+body, etc.) |
| HMAC key | 13 (empty, zero16/20/64, build, devid, appid, mask15/16, etc.) |
| 切片偏移 | 6 (slices [0:15] through [5:20]) |
| **组合** | **14 × (13+1) × 6 = 1176 per sample** |

测试了 `/api/model_portrait/detect_items` + 3 个 note API + 1 个 POST with body。

**结果：全部未命中。** SHA-1 确实在用，但 canonicalize 的构造方式**不是任何简单字符串拼接**。

### 确认的辅助性质

- 329 个 shield 里有 **11 个重复**（不同请求同一 shield），说明某个决定性 input 在这些请求里恰好相同
- 同一 URL 的重复请求（53 组）**全部 shield 不同**，说明 shield 依赖于真正的 per-request 数据（不只是 URL）

### 静态分析的真正瓶颈

SHA-1 的 init/update/final 全部定位清楚，但 shield 真正的**构造公式**无法通过纯静态枚举得到，因为：

1. canonicalize 实际内容不是 `path+query+xpi` 原文
2. hash 输入可能经过 hex 编码 / 双层 HMAC / 盐前后缀等变换
3. key 可能运行时派生，不是任何静态常量

**唯一能突破的路径是在 sha1_update 调用瞬间 dump r1 指向的内存**。三条子路径：

- **A. 修好 sha1_final 的 emulation**：当前 366 指令即退出（CFG flatten 走歪），修好后能作为 SHA-1 oracle 实时验证任意候选
- **B. 扩展 run_intercept_v2.py 让 shield_builder 跑完**：需要 fake Chain/Request 对象图 + JNIEnv vtable stub，成本高但是**最直接**的路径
- **C. Frida 真机 hook** dump 一次 message bytes —— 超出"纯静态"范围

### 第八轮结束状态

| 组件 | 状态 |
|---|---|
| libxyass 字符串表解密 | ✅ 4 个加密字符串纯 Py 解出（byte-exact）|
| crypto primitive 识别 | ✅ SHA-1 三个函数全部定位，ctx 布局已知 |
| shield 二进制布局 | ✅ prefix=85B + tail=15B（329 样本统计验证）|
| device_mask 纠正 | ✅ 15B `d17cdfa2bb91e9947b3b485623f7bb` |
| shield 调用链 | ✅ intercept → [vtable] → 0x24bcc → 0x2acb0/0x2ad80/0x2b27c + base64@0x286d0 |
| **canonicalize 公式** | ❌ 1176 组合全部未命中，需要动态 message dump |

## 第九轮：shield_builder emulation 成功到达 sha1_update 入口

### 🎯 关键突破

按第八轮的建议走"方案 B（扩展 shield_builder runner）"，这轮把 [run_intercept_v2.py](../scratch/ghidra_work/run_intercept_v2.py) 加了 4 项关键补丁，**成功让 emulation 跑到 `bl 0x2ad80` 的调用点**，并 dump 出 `r1/r2` 的真实内容。

### 4 项补丁

1. **Pre-text guard**（`PC < 0xd760` = ELF header 区）
   当 fake vtable 返回 0 → blx 跳到 PC=0 → PC 开始读 ELF 头字节作指令，自动 stub-return 让执行继续
2. **PLT auto-stub**（`0x76640 <= PC < 0x76900`）
   所有 PLT 入口统一 return 0，避免 GOT 未解析的导入函数导致崩溃
3. **Vtable wrapper 旁路**
   `0x1edf8` / `0x1ee34` 是 thin C++ dispatcher（`ldr r3, [r0]; ldr r4, [r3, #0x8c]; blx r4` 模式）。Unicorn 对它里面的 IT 块处理有 bug，直接把这俩当"读 r0 的 vtable[offset] → 跳过去"的 stub 处理，避开 IT-block bug
4. **Thumb bit preservation**
   PC 写回时用 `lr | 1`（而不是 `lr & ~1`）保持 Thumb 模式——Unicorn 通过 LSB 感知模式切换，清零会进入 ARM 模式然后在下一条指令崩掉

### 运行结果

```
*** ENTER SHIELD_BUILDER @ 0x24bcc ***
    r0=0x50000000 r1=0x50000600 r2=0x0
*** ENTER SHA1_UPDATE @ 0x2ad80 ***  trace_idx=94381
    r0=0x7003df34 r1=0x50001300 r2=65 (after slot-50/176 stubs)
    msg (65B): b'\x00\x13\x00P\x41\x00\x00\x00\x00\x01\x00\x00CANON_PROBE_123456789_ABCDE...'
*** ENTER SHA1_UPDATE @ 0x2ad80 ***  trace_idx=188657
    (second call, same pattern)
```

**r1 指向的字节完全可控**——shield_builder 在调 `sha1_update(ctx, r1, r2)` 之前，r1 是**我们 stub 的 slot 184 返回的对象地址**。把 slot 184 返回的对象用 `CANON_PROBE_123456789_ABCDE...` 填充后，sha1_update 的 r1 指向的前 65 字节就是我们的探针字节。

### 确认的数据流

从 capstone 反汇编 + emulation trace 交叉印证：

```
chain.vtable[0x8c]     (slot 35, helper 0x1edf8)   → some chain getter
chain.vtable[0x2c0]    (slot 176)                 → ? (r6)
chain.vtable[0xc8]     (slot 50, helper 0x1ee34)  → 长度 (r8 → r2 of sha1_update)
chain.vtable[0x2e0]    (slot 184)                 → 数据对象 (sb → r1 of sha1_update)
chain.vtable[0x300]    (slot 192)                 → loop 内部，继续处理
↓
bl 0x2ad80 (sha1_update) 被调用至少 2 次（在 0x24c72 的分块循环里）
```

这意味着 **shield 的 SHA-1 输入来自 `chain.vtable[0x2e0](chain)` 返回的对象的前 N 字节，N 来自 `chain.vtable[0xc8](chain)`**。

### 关键洞察：SHA-1 输入的对象布局

当 slot 184 返回一个 std::string-like 对象（我们 fake 时按 `[data_ptr][size][cap][inline_data]` 布局），sha1_update 读取的 65 字节包括：
- 前 12 字节是对象元数据（ptr + size + cap）
- 后 53 字节开始是实际的字符串数据

**在真实执行里**，slot 184 返回的可能是：
- A) std::string 对象指针，长模式 → 前 12 字节是元数据（但元数据里的 ptr 是运行时值，不能参与稳定签名）
- B) std::string 对象指针，SSO 模式 → 前 23 字节是内联字符串
- C) **简单的 `const char*` 指针** → 整个 65 字节直接就是字符串内容

最合理的是 (C)：**slot 184 返回 char*，shield_builder 读取 char* 的前 len 字节作为 canonicalize**。

### 仍然不知道的

**真实 `chain` 的 vtable[0x2e0] 具体返回什么字符串**——这是一个 C++ 虚函数，实现可以是任何东西：
- 动态构造的 canon 串（最可能）
- 某个缓存的字符串
- 来自 Java 侧传入的字节数组

要知道它的返回，**需要静态反编译**这个虚函数的实现。但我们不知道这个虚函数的地址，因为 chain 本身是由调用 XhsHttpInterceptor 的 Java 层传下来的，vtable 是动态绑定的。

### 下一轮的明确路径

1. **静态追 C++ chain 类型**：从 JNI_OnLoad 或 intercept 的 `cPtr` 构造处找到 chain 类的 vtable 地址，然后看 vtable[0x2e0] 实际指向的函数体。这个函数体就是 canonicalize 的生成器，里面会构造实际的 SHA-1 输入
2. **或**：直接扩展 emulator 让 shield_builder 跑完一次完整循环，观察 sha1_final 输出，并把 fake chain 的数据**反复变换**，看哪些字节组合能产生 target hash —— 这是"emulator 作 oracle"的 hypothesis search

### 本轮 run_intercept_v2.py 的能力

现在这个 harness 已经是一个**实用的 shield builder 沙箱**：
- 执行到 `bl 0x2ad80` 命中率 100%
- `r1` / `r2` 完全可控（通过 slot 184 / slot 50 stub）
- 可以喂任意 canon 候选进去，观察 sha1_update 收到的字节
- 未来配合 sha1_final oracle 可以成为完整的 shield 验证器

## 第十轮：两个重大纠正 + 大量先前未知字符串

### 🎯 纠正 1：sl 是 JNIEnv*，不是 Chain C++ 类

第九轮里我把 `shield_builder (0x24bcc)` 的 r1 参数（保存为 sl）以为是一个 C++ Chain 对象，调用 `chain.vtable[offset]` 读 virtual method。**实际上 sl 就是 JNIEnv\***，所谓的"vtable"是 JNI 函数表。

按标准 Android JNI 1.6 索引表：

| 偏移 | Index | JNI 函数 |
|---|---:|---|
| 0x8c | 35 | CallObjectMethodV |
| 0xc8 | 50 | CallIntMethodV |
| 0x2c0 | 176 | **NewByteArray** |
| 0x2e0 | 184 | **GetByteArrayElements** |
| 0x300 | 192 | ReleaseByteArrayElements / SetByteArrayRegion |

所以前几轮看到的"vtable dispatch 的 slot 184"其实是 **GetByteArrayElements**——**shield 的 SHA-1 输入来自一个 Java byte[] 数组**，native 通过 `GetByteArrayElements` 拿到 C 指针，`NewByteArray` 先创建 array，`SetByteArrayRegion` 或 `CallIntMethodV` 填充内容。

### 🎯 纠正 2：libxyass 字符串表有 30+ 条，不是 4 条

我第五轮宣布 "libxyass 只有 4 个加密字符串"——**完全错**。[scratch/ghidra_work/decrypt_hunt.log](../scratch/ghidra_work/decrypt_hunt.log) 是上一会话更早时期的产物，用另一种 hunt 方法（追 JNI_OnLoad 执行路径）已经解出了 **30+ 条加密字符串**：

#### JNI 类名（17 条 okhttp3 / Android / java）

```
okhttp3/Interceptor$Chain
okhttp3/Request
okhttp3/Request$Builder
okhttp3/HttpUrl
okhttp3/RequestBody
okhttp3/Headers
okhttp3/Response
okhttp3/ResponseBody
okio/Buffer
com/xingin/shield/http/Native
com/xingin/shield/http/ContextHolder
com/xingin/shield/http/Base64Helper
android/app/Application
android/content/Context
android/content/SharedPreferences
android/content/SharedPreferences$Editor
android/content/pm/PackageManager
android/content/pm/PackageInfo
android/content/pm/Signature
[Landroid/content/pm/Signature;
java/lang/String
java/util/List
java/nio/charset/Charset
```

#### JNI 方法名 + 签名

```
initializeNative()
intercept (Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;
initialize
destroy
getPackageManager ()Landroid/content/pm/PackageManager;
getPackageInfo (Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
getPackageName ()Ljava/lang/String;
signatures (field)
hashCode ()I
```

**这些字符串揭露了 libxyass 的完整 Java 交互面**：它不仅调用 Chain/Request/HttpUrl 获取 URL 数据，还读 Application 的 PackageManager → PackageInfo → signatures[0].hashCode() 来拿到 **APK cert hash**！这个 hash 很可能就是 HMAC-SHA1 的 key！

### 🎯 shield 生成的真实架构（纠正后）

现在能画出更准确的流程：

```
Java: Native.intercept(chain, cPtr) called from XhsHttpInterceptor
   ↓
libxyass Java_com_xingin_shield_http_Native_intercept (= 0x23e54 intercept)
   ↓
1. JNI: getPackageManager() → PackageInfo → signatures[0].hashCode() → int  (APK cert hash)
2. JNI: chain.request() → request → url, headers, body (via okhttp3 method calls)
3. Native: 构建 canonicalize 字节流（path + query + xy-platform-info + body? + ...）
4. Native: 将 canonicalize 写入一个 Java byte[]
5. Native: sha1_init(ctx); sha1_update(ctx, key_xor_ipad); sha1_update(ctx, msg); sha1_final(ctx, inner_hash)
                          ↑ key 很可能是 cert hash 的某个派生
6. Native: sha1_init(ctx); sha1_update(ctx, key_xor_opad); sha1_update(ctx, inner_hash); sha1_final → outer_hash
7. Native: shield_tail = outer_hash[0:15] XOR device_mask
8. Native: shield = device_prefix || shield_tail; base64 encode (via 0x286d0)
9. JNI: Response Builder 设置 header "shield" 和 "xy-platform-info"
```

### ⚠️ 另一个候选 hash：0x174c8

上一个会话的 [run_intercept.log](../scratch/ghidra_work/run_intercept.log) 显示 intercept 直接 bl 的是 `0x174c8`，**调用了 3 次**（at 0x23fce, 0x24134, 0x2436a），每次签名都是 `(r0=out, r1=in_ptr, r2=len, r3=?)`。第一次调用时 r1 指向 `"/api/tes"` (路径前 8 字节)，r2=8。

这说明 intercept 有一个**流式 hash 函数** `0x174c8`，被调用 3 次处理不同的输入块。可能是：
- A) 流式 SHA-1 (init + update + final 合一的 oneshot)
- B) 完全独立于 sha1_init/update/final 的另一个 hash
- C) 某种 build-up 函数而非 hash

0x174c8 的反汇编起始处看起来像**跳转表**（多条 `b #0x178xx` 均匀分布），可能是 switch-over-length 的优化分支。

### 第十轮结束状态

| 组件 | 状态 |
|---|---|
| JNIEnv slot 映射 | ✅ slot 184/176/50/35 = GetByteArrayElements/NewByteArray/CallIntMethodV/CallObjectMethodV |
| libxyass 字符串表 | ✅ 30+ 条已解（先前会话），覆盖 okhttp3 / Android / java 类名 + JNI 方法 + 签名 |
| shield 数据源 | ✅ 通过 JNI 从 Chain 对象调方法获取 URL + headers + body |
| **HMAC key 候选** | 🎯 APK cert hash（`signatures[0].hashCode()` 返回的 int）— 可在 Python 里直接计算测试 |
| `0x174c8` 的角色 | ⚠️ 可能是另一个 hash 函数，需单独反编译确认 |
| canonicalize 的精确构造 | ⚠️ native 侧拼接，需要 trace JNI 调用序列还原 |

### 下一轮路径

1. **直接测试 cert-hash-as-HMAC-key 假设**：用 xhs APK 的签名 SHA-1 计算 `signatures[0].hashCode()`（Java 的 int hashCode，可在 Python 里复现），然后 `HMAC-SHA1(that_int_as_bytes, canon)[0:15] XOR mask == shield_tail`？
2. **重新跑 decrypt hunt**：用更完善的扫描找出 libxyass 里**全部**加密字符串（不只是 decrypt_hunt.log 的 30 条），为 JNI trace 做准备
3. **反汇编 0x174c8 确认用途**：它是不是 sha1_init+update+final 的 oneshot？还是一个完全独立的 hash？

### 第十一轮：0x174c8 是 memcmp + libxyass 完整导入清单

#### 🎯 0x174c8 = memcmp（之前的错判纠正）

上一轮我把 `0x174c8` 当作 "可能是另一个 hash 函数"。本轮实锤：

1. **3 个调用点都是 `blx #0x174c8`**（不是 `bl`）——`blx` T2 编码切换到 ARM 模式执行目标
2. **0x174c8 的第一条 ARM 指令是 `B 0x767f0`**——无条件跳到 `.plt` 区
3. **解析 `.rel.plt` 后确认**：`0x767f0` 是 PLT 槽 34 → `memcmp`（通过 R_ARM_JUMP_SLOT 映射到 `.dynsym`）
4. 紧挨着的还有 `B 0x76820` → `pthread_rwlock_init`，`B 0x767c0` → `fflush`——**整段是 ARM-mode 的 veneer/thunk 表**，每一个是一个外部库函数的包装

所以 intercept 的 3 次 `blx #0x174c8` 都调用 `memcmp(buf, "/api/tes", 8)`——**用来判断 URL 路径前缀分类**，和 hash 无关。

#### 🎯 libxyass 完整外部依赖清单（42 个 PLT + 54 个 dynsym 条目）

**全部是标准 libc / pthread / stdio**，没有任何 crypto 库：

```
libc: malloc, free, realloc, posix_memalign, memcpy, memset, memmove, 
      memchr, memcmp, strlen, strcmp, strncmp, sprintf, snprintf, 
      vfprintf, fprintf, fputc, fflush, vasprintf, syscall, time, uname
      __stack_chk_fail, __cxa_finalize, __cxa_atexit, __assert2, abort
pthread: mutex_lock/unlock, cond_wait/broadcast, rwlock_*, key_create/delete,
         getspecific/setspecific, once
dl: dl_unwind_find_exidx
```

**关键含义**：
- libxyass **没有链接 OpenSSL / BoringSSL / Bouncy Castle / 任何 crypto 库**——所有 crypto 原语都是**内置实现**（MD5 T 表、SHA-1 init/update/final 都是手写的 ARM 代码）
- 依赖的导入里**没有 JNI 函数**——JNI 调用都走 `JNIEnv*` 函数表（动态），不走 .rel.plt
- 大量 `memcpy/memset/memmove/strlen/sprintf` 说明 **canonicalize 构建是在 native 里手工拼接字符串**，不走任何高级库

#### 静态 RE 到这里的完整图景

现在所有宏观架构问题都有答案：

```
libxyass 的 shield 生成流程（确认）：

Java: XhsHttpInterceptor.intercept(chain) → Native.intercept(chain, cPtr)
                                               ↓
libxyass Java_..._intercept (0x23e54):
  1. 用 memcmp 判断 URL 前缀（0x23fce/0x24134/0x2436a 三次，用于路径分类）
  2. 通过 JNIEnv* 调用 chain.request() / request.url() / url.encodedPath() 
     / url.query() / request.headers() / request.body() 等
  3. 用 GetStringUTFChars / GetByteArrayElements 把 Java 数据拉到 native 缓冲
  4. 用 memcpy / sprintf 拼接 canonicalize 到 Java 侧的 byte[]
  5. 调用 shield_builder (0x24bcc)：
     - 从 byte[] 取 C 指针
     - sha1_init(ctx)
     - sha1_update(ctx, msg, len)    ← 本轮跑通的调用点
     - sha1_final(ctx, out)
     - outer 层 HMAC-SHA1（或直接 SHA-1）
  6. shield_tail = hash[0:15] XOR device_mask
  7. 前 85B 是 device_prefix（ContextHolder.sDeviceId + APK cert 派生的常量）
  8. base64 编码 (0x286d0)
  9. 通过 JNI 调 Request.Builder.header("shield", b64).header("xy-platform-info", xpi_value)
 10. chain.proceed(newRequest)
```

#### 第 11 轮结束状态

| 发现 | 状态 |
|---|---|
| 0x174c8 身份 | ✅ memcmp（不是 hash）|
| libxyass 外部依赖 | ✅ 42 PLT / 54 dynsym 全部纯 libc |
| JNI 调用架构 | ✅ 通过 JNIEnv* 函数表，不走 .rel.plt |
| Crypto primitives | ✅ 全部内置（SHA-1 + MD5 + base64）|
| 字符串表 | ✅ 30+ 条已解，包含全部 okhttp3/Android 类名 |
| shield 宏观流程 | ✅ 从 Java intercept 到 base64 输出全链条已画出 |
| 微观 key/msg 构造 | ⚠️ 仍需动态 JNI trace 才能拿到精确字节序列 |

### 下一轮（第 12 轮）明确目标

这一步**必须扩展 run_intercept_v2.py 从 intercept() 的入口跑**（不是 shield_builder），并且：
1. Stub 掉 JNIEnv 的完整 233 个函数槽，每个 slot 记录 (slot_idx, args, return)
2. 对 FindClass/GetMethodID 返回 canonical handles，并记录 class+method+signature 到一个字典
3. 对 CallObjectMethod/CallStaticMethod 查 methodID → "chain.request" / "request.url" 之类的映射，返回对应的 fake 对象
4. 对 GetStringUTFChars 返回预定义的 marker 字符串（路径、查询、header 等每个一个独特的）
5. 让 intercept 跑到 sha1_update，观察 r1 里的字节里包含哪些 marker

这会给出"canonicalize 的 native 构建顺序"的 **完整 ground truth**。然后在 Python 里用 `hashlib.sha1` 复现即可。

预计这一轮需要把 run_intercept_v2.py 的 JNI 部分大幅扩展（从当前 ~200 行到 ~500 行），但架构已经画清楚，实现是有限工程。

## 第十二轮：shield_builder 的 JNI 调用序列完整解码

### 🎯 突破：标记追踪 + JNI 修正后，完整看清 data flow

本轮修复了 `_handle_chain_method` 里的两个 JNI 语义错误：
1. **slot 184 `GetByteArrayElements`** 之前返回的是 object pointer（当成 std::string 了）。实际它应该返回**纯粹的 byte\***，指向 Java byte[] 的原始数据
2. **slot 34/35/36 `CallObjectMethod[VA]`** 现在返回一个 fake jobject handle（`0xca11xxxx`）

修复后把 shield_builder 的输入参数用不同 marker 标记 (`r0=0xDEAD`, `r2=0xBEEF`, `r3=0xCAFE`)，重跑看哪个 marker 流进 JNI 调用。

### JNI 调用序列（从 emulation trace 提取）

```
bl 0x24bcc(r0=DEAD0000, r1=env, r2=BEEF0000, r3=CAFE0000)
  ↓
slot 35 (CallObjectMethodV):
    env->CallObjectMethodV(env, 0xBEEF0000 /* 来自 r2! */, methodID_A, va_list)
    → 返回 0xca110001 (fake obj)
  ↓
slot 176 (NewByteArray):
    env->NewByteArray(env, 0x1000 /* 4KB */)
    → 返回 0x50000600 (new byte[])
  ↓
slot 50 (CallIntMethodV):
    env->CallIntMethodV(env, 0xca110001, methodID_B, va_list)
    → 返回 65 (= 长度)
  ↓
slot 184 (GetByteArrayElements):
    env->GetByteArrayElements(env, 0x50000600, NULL)
    → 返回 byte* 指向 NewByteArray 的数据
  ↓
bl 0x2ad80 (sha1_update):
    sha1_update(ctx, byte_ptr, 65)   ← 这就是 SHA-1 的真实输入！
  ↓
slot 192 (ReleaseByteArrayElements)
```

### 架构含义

1. **shield_builder 的 r2 参数是一个 Java 对象**（标记 `0xBEEF0000` 原样出现在 CallObjectMethodV 的 obj 参数里），不是 byte[] handle
2. native 侧把 r2 当成**数据源**（DataSource / InputStream-like），调 method A 获得一个派生对象（可能是 body / buffer / source）
3. 然后**新建一个 4KB 的 Java byte[]** 作为目标 buffer
4. 调 method B（CallIntMethodV）从源读数据到 buffer，返回读取的字节数
5. 再通过 GetByteArrayElements 拿 C 指针 → sha1_update

### 最可能的 Java 模式

这是经典的 **"read into buffer"** JNI 模式。候选 Java 方法：

- `java.io.InputStream.read(byte[] b)` — 返回读取字节数，**签名 `([B)I`**
- `okio.BufferedSource.read(byte[] sink)` — okio 版本，同样签名
- `okio.Buffer.read(byte[] sink)` — okio Buffer 读取，签名 `([B)I`
- `okhttp3.RequestBody.writeTo(BufferedSink)` 后 `Buffer.readByteArray()`

考虑到之前解密出的字符串表里有 `okio/Buffer` 和 `okhttp3/RequestBody`，**最可能是 `okio.Buffer.read([B)I`**。

### shield_builder 的 r2 是什么？

**r2 是调用 shield_builder 前 intercept 准备好的一个 Java 对象**，类型最可能是 `okio.Buffer`。这个 Buffer 已经被填充了 canonicalize 的字节内容。

所以 intercept 的宏观流程（再次修正）：

```
intercept():
  // 步骤 1: 从 Java 侧抽取请求数据
  request = env->CallObjectMethod(chain, method_request)
  url = env->CallObjectMethod(request, method_url)
  path = env->CallObjectMethod(url, method_encodedPath)
  query = env->CallObjectMethod(url, method_query)
  headers = env->CallObjectMethod(request, method_headers)
  body = env->CallObjectMethod(request, method_body)
  
  // 步骤 2: 在 native 侧构造一个 okio.Buffer，
  //         把 path + query + xy-platform-info + ... 以某种格式写入
  //         (通过 JNI 调 Buffer.writeUtf8 / Buffer.write)
  canon_buffer = env->NewObject(Buffer_class, Buffer_init)
  env->CallObjectMethod(canon_buffer, method_writeUtf8, path_jstring)
  ... repeated for query, xy-platform-info, etc. ...
  
  // 步骤 3: 调 shield_builder 把 canon_buffer 传进去
  shield_builder(r0, env, canon_buffer, r3)
    ├─ okio_obj = canon_buffer.source()   (or similar)
    ├─ temp_byte_array = env->NewByteArray(4096)
    ├─ nbytes = okio_obj.read(temp_byte_array)   ← 65 bytes returned
    ├─ raw_ptr = env->GetByteArrayElements(temp_byte_array)
    ├─ sha1_init + sha1_update(ctx, raw_ptr, nbytes) + sha1_final
    └─ env->ReleaseByteArrayElements(temp_byte_array)
```

### 下一轮明确起点

要知道 **canon 的精确构造**，必须定位 intercept 里**步骤 2**：哪些 JNI 调用把 path/query/xpi/body 写入了 okio.Buffer？这是一连串 `Buffer.writeUtf8 / Buffer.write(byte[])` 类的 JNI 调用。

具体做法：
1. 继续扩展 `run_intercept_v2.py` 让它从 intercept() 入口（0x23e54）跑而不是 shield_builder
2. 给每个 JNI `CallObjectMethodV` 的 methodID 分配不同 ID 并在 trampoline 里记录
3. 对 `NewStringUTF` / `GetStringUTFChars` 返回不同的 marker 字符串，对应每个可能的 canon 组件
4. 追到 shield_builder 的调用点，观察 r2 对应的 okio.Buffer 是哪个 Java 对象 handle，回溯到是哪些 JNI 调用填充的

**这一步不复杂**但需要扩 JNIEnv 的全 233 slot trampoline。下一轮完成后，就能得到 canonicalize 的完整构造公式。

## 第十三轮：确认 intercept 静态追踪的硬瓶颈 + 最终状态

### 🎯 为什么 intercept() 端到端 emulation 停住了

本轮尝试让 [run_intercept.py](../scratch/ghidra_work/run_intercept.py) 从 intercept 入口（0x23e54）跑到 shield_builder（0x24bcc），观察中间的 JNI 调用序列。结果：

**PC 停在 0x23fde**（memcmp 后第 5 条指令）：

```asm
0x23fce  blx  #0x174c8        ; memcmp (stub返回0 → equal)
0x23fd2  ldr.w fp, [sp, #0x5c]  ; fp = *(sp+0x5c)  ← 栈槽未初始化
0x23fd6  movs r0, #0
0x23fd8  strb r0, [r5, r6]
0x23fda  ldr.w r0, [fp]         ; r0 = *fp          ← fp 是垃圾值
0x23fde  ldr.w r3, [r0, #0x2a8] ; r3 = r0[0x2a8]   ← 访问非法地址崩溃
```

`sp+0x5c` 在我的 emulator 中是初始化为 0（栈初始零），所以 `fp=0` → `*fp` = 崩溃。真实执行里，intercept 在更早的代码路径会给 `sp+0x5c` 写一个有效的 JNI 对象指针（可能是 chain 或 env 的缓存）。

要解决需要反汇编 intercept 的**前 80 条指令**找到所有 `str rN, [sp, #X]` 并跟踪它们的值来源，然后在 emulator 里预先 seed 那些栈槽。这是明确工作但**手工工作量较大**（intercept 的栈帧有 ~60 个 local 变量）。

### 🎯 又一轮广谱假设测试全军覆没

本轮对 session2 的 3 个 note API 请求做了**最彻底**的 SHA-1 / HMAC-SHA1 假设搜索：

| 维度 | 候选数 |
|---|---|
| canon 公式 | **~30 种** (含 HTTP wire format、body 组合、host 前缀、okhttp3 url.toString 等) |
| HMAC key | **~17 种** (含 cert.hashCode() 的 LE/BE u32、deviceId 各种编码) |
| 切片偏移 | 6 |
| 2 种 tail layout | 15@85 + 16@84 |
| **总组合** | **6120 per sample** |

**零命中**。这是第 8 轮（1176 组合）之后的第 2 次彻底否认简单假设的存在。canon 构造**不可能是任何明显的 path+query+xpi+body 字符串拼接**。

### 🎯 静态 RE 到此为止的能力边界

13 轮走下来，**每一层宏观架构问题都有答案**：

| 项目 | 状态 |
|---|---|
| libxyass 加载 + 字符串解密 | ✅ 30+ 条已解（okhttp3/Android/JNI 方法名）|
| libxyass 外部依赖 | ✅ 全部纯 libc/pthread，无 crypto 库 |
| Shield hash 算法 | ✅ SHA-1（Unicorn 执行 init 确认 h4=0xc3d2e1f0）|
| Shield 二进制布局 | ✅ 85B prefix + 15B tail（329 样本熵分析）|
| Device mask | ✅ 15B `d17cdfa2bb91e9947b3b485623f7bb` |
| SHA-1 函数入口 | ✅ init=0x2acb0, update=0x2ad80, final=0x2b27c |
| shield_builder JNI 模式 | ✅ "read into buffer": NewByteArray → Buffer.read → GetByteArrayElements → sha1_update |
| shield 调用链 | ✅ Java intercept → Native intercept → shield_builder → sha1{init,update,final} → base64 |
| APK cert 使用 | ✅ 通过 PackageManager→PackageInfo→signatures[0].hashCode() |
| Java 侧 11/16 头 | ✅ byte-exact 纯 Py |

**剩下的最后一公里只有一项**：

| 项目 | 状态 |
|---|---|
| canonicalize 的 native 构造序列 | ❌ 需要运行 intercept 到 shield_builder 来观察 |

### 🎯 突破这最后一公里的三条路径

**A. 全 JNIEnv stub + intercept 逐 JNI trace**（纯静态，multi-day）
扩展 run_intercept_v2.py 到：
- 完整 233 slot JNIEnv trampoline
- FindClass / GetMethodID 记录 `{class_name, method_name, sig} → methodID` 字典
- 对每个 CallObjectMethodV 根据 methodID 查表返回正确的 fake 对象类型
- 对每个 `sp+X` 栈局部变量的依赖做预先 seed
- 对条件分支用 `r5/r6 = forced_value` 强制走到 shield_builder
- 追踪 Buffer.writeUtf8 / Buffer.write 的调用序列 → 得出 canon 构造

预计工作量：**2-3 人日**。纯静态。最终能给出 canon 精确字节序列。

**B. Frida 单次 hook**（violates 静态约束，~30 分钟）
在真机上 hook 0x2ad80 入口一次，dump `r1/r2`。拿到 (msg_bytes, msg_len) 后可以：
- 直接对比 hashlib.sha1(msg_bytes) == 某个真实 shield 的推导
- 反向拆解 msg_bytes 看里面是哪些头/URL/body 的拼接方式

拿到 canon 的真实字节后，static RE 重启：在 Python 里复写 canon 构造器即可。

**C. 针对性 emulator 补丁**（纯静态，half-day）
不跑完整 intercept，而是：
- 反汇编 intercept 的 prologue（约 80 条指令）
- 手工提取每个 `str rN, [sp, #X]` 的栈局部初始化
- 在 emulator 里预先 seed 这些栈位
- 只跑到需要的 bl 点位（如 shield_builder 的调用点）

这是 A 的"微型版本"——不做完整 JNI 模拟，只做够 intercept 跑到 shield_builder 需要的栈状态。

### 🎯 我的判断：选 **C**

- A 投入产出比低（2-3 日工作量换一次数据）
- B 最快但违反"纯静态"约束
- C 是 "half day 静态工作 + 直接拿到 canon 构造" 的最佳折中

C 具体步骤：
1. 反汇编 intercept 0x23e54..0x23fde，找到所有栈位初始化指令
2. 预先计算每个栈位应该有的值（从 JNI 返回 / 常量 / env 字段）
3. 在 run_intercept.py 里 seed sp+0x5c, sp+0x6c 等栈位
4. 让执行跑过 0x23fde 的崩溃点
5. 继续跑到 shield_builder 的调用点，观察 r2 对应的 buffer 里已写入的字节

这是**下一轮的明确、有限工作量**。而不是继续在有 2700-6000 组合的搜索空间里盲目枚举。

### 本轮（第 13 轮）终结状态

- **intercept 静态 emulation 的瓶颈明确**：sp+0x5c 等栈局部未初始化
- **广谱假设 6120 组合零命中**，确认 canon 不是简单字符串拼接
- **三条突破路径识别**，推荐走 C（栈种子 + 针对性 emulation）

13 轮完整的静态 RE 已经把 shield 从"完全黑盒"推到"只差 canon 字节序列"。下一轮用栈种子让 intercept 多跑 ~50 条指令，就能看到那个 okio.Buffer 里写入的具体字节，canon 就解了。

## 第 14 轮（2026-04-15）: shield_builder 端到端 emulation 跑通

### 14.1 方法转向
放弃完整 intercept() emulation（需要 strlen + 大量 PLT stub）。改为直接把 `shield_builder (0x24bcc)` 当作接受 4 个 arg 的纯函数调用。绕过 JNI 前缀逻辑，直达 shield 生成核心。

### 14.2 JNI trampoline 完整化
`run_intercept_v2.py::_handle_chain_method` 按 slot 精细分派：
- 35 (CallObjectMethodV), 176 (NewByteArray), 50 (CallIntMethodV)
- 184 (GetByteArrayElements) → 返回每次循环不同的 `CHUNK0N_XXX...` marker
- 192 (Release/SetByteArrayRegion), 23 (DeleteLocalRef — post-loop cleanup)

### 14.3 外层循环退出条件
`0x24d40: adds r0, #1; bne #0x24c72` — 前一条 `blx r5`（非 trampoline 的动态跳转，通过 `r5 = [[sp+0x24]+4] + 0xb62ec14` 拼出）返回 `-1` 退出。PC hook 强制 `r0 = -1` 后 N 次即可让循环跑完。

### 14.4 shield_builder 完整流程解码
```
1. sha1_init(ctx = sp+0x34)                      标准 SHA-1 IV
2. 外层循环 × N：
     CallObjectMethodV → NewByteArray → [
         CallIntMethodV(len)
         GetByteArrayElements(data)
         sha1_update(ctx, data, len)   ← 0x24cfa
         Release
     ] × N
     indirect blx r5 == -1 时退出
3. sha1_final(ctx, out = sp+0xc0)                20B inner digest
4. 模式分派（由第 4 arg 指向的 struct 决定）：
     [r3+0] == 6 → bl 0x2b838   (HMAC-like, 64B key, 16B out)
     [r3+0] == 7 → bl 0x3329c   (不同 MAC, 可能 AES-GMAC)
     其它        → fallback 0x01010101
5. 16B 输出经 vld1.8 {d16, d17} 拷到堆 result
```

### 14.5 关键发现
1. **canonicalize 是"流"式**：不是预先拼好的 buffer，而是循环里多次从 JNI 取 byte[] 逐次喂给 sha1_update。canon 的本质是 _一组 byte[]_。
2. **0x24cd0 附近有个 hex 编码器**：用查表法（`r3[nibble]`）把每字节展成两个 ASCII hex 字符写入 `sp+0x34`，是 scratch 用途（debug log？），_不_ 进入 hash。
3. **模式 tag 在 r3 arg 指向的 struct 首字段**：caller 决定用哪种 MAC。shield_builder 本身是通用 signer。
4. **0x2b838 固定 16B 输出**，和 shield tail 长度完美吻合。
5. **HMAC-SHA1(probe_key, inner_digest) ≠ 0x2b838 输出** → 0x2b838 _不是_ 标准 HMAC-SHA1。输出 `537a7c2f4158dee8cfe02283af666467` 是确定性的，但不匹配 Python hashlib 任何变体组合。可能是自定义 pad 常量 / 改动的 outer hash / byte-mixer 变换。

### 14.6 可重复的纯 Unicorn emulation
现在可以用任意 canon 输入驱动 shield_builder：
- 改 slot 184 payload → 控制 sha1_update 吃什么
- 改 out_buf struct → 控制 MAC key
- 从 `_out_buf_slot` / `_hmac_args['out_ptr']` 读最终 16B 输出

**shield_builder 从黑盒 → 白盒**。下一轮只要：
1. CHUNK marker 换成真实 canonicalize bytes
2. probe_key 换成真实 HMAC key（.bss / device_id 派生）
3. 比对抓包 shield tail 验证

### 14.7 未解小谜团
- **0x2b838 算法**：非标准 HMAC-SHA1，内部有 24× sha1_update(r2=1) 的奇怪模式，需单独 RE
- **canon 字节真实来源**：需要把循环每次 GetByteArrayElements 追到 Java 侧的哪个字段
- **HMAC key 来源**：struct 由 intercept caller 准备，需要追 caller 的 r3 构造逻辑

## 相关文件

- 纯 Py 代码：[unicorn/py_signer/](../unicorn/py_signer/)
- Ghidra 工作目录：[scratch/ghidra_work/](../scratch/ghidra_work/)
- 抓包文件：`lsposed/xhs-capture/captures/xhs_capture_20260413_162400.log`
- 本文前置分类：[docs/33_header_source_classification.md](33_header_source_classification.md)

## Rounds 14-20 总结 (2026-04-15/16): `shield_mac16.py` 终态

### 算法完整架构

`0x2b838` 是一个 **自定义 Murmur-family 4-word keyed hash**，输入 64B key + 20B msg → 16B tag。不是任何已知标准 MAC。

```
mac16(key_64B, msg_20B) → tag_16B

_opaque_setup(key, msg):          [Unicorn — 唯一黑盒]
  └── Stage 1: 初始化 + key[1,2,9,14] packing + msg embedding
  └── Stage 2 main loop: 4 iterations × MurmurHash-style round
      state = (IV, IV, IV, IV);  IV = 0x7135188b
      for each 16B key block:
        (s0,s1,s2,s3) = round(s0,s1,s2,s3, w0,w1,w2,w3)
  └── Post-main: mix state + msg → 9 u32 + byte + stack bytes
      *** 包含 ELF header 自读（反逆向） ***

_compute_2cc(key):                [Pure Py]
  = (key[1]<<24) | (key[2]<<16) | (key[9]<<8) | key[14]

_stage2_end_transfer(packed, v334..v350):  [Pure Py]
  Block 1: OR-pair-mul-xor-ror-mul5-add-const (4 outputs)
  Block 2: msg passthrough + ror19/ror14 cross-deps (5 outputs)

_stage3(s_2d8..s_2f4, 3_stack_bytes):     [Pure Py]
  6 outputs, same Murmur-style pattern, 0x30c = byte packing

_stage4(in_2f8..in_30c, byte_val):         [Pure Py]
  OR-pair-mul-xor24-add-chain (4 outputs, with xor13-mul cross-stage)

_stage5(in_314..in_320):                   [Pure Py]
  Asymmetric MurmurHash3 fmix32 (4 branches, 2 full + 2 split)

_finalize(h0,h1,h2,h3):                   [Pure Py]
  m = h0 * 0xa3b2ce45; m ^= m >> 16
  output = [h1+h2+h3+m, ..+h2, ..+h3, ..+m]
```

### Magic 常量 Complete Index

| 常量 | 用途 |
|---|---|
| `0x7135188b` | Stage 2 IV（4 word 初始值） |
| `0x229c952a` | MX1: round/end-transfer mul |
| `0x254a8000` | MX2: round/end-transfer mul |
| `0xac1e4678` | MX3: round/end-transfer mul |
| `0xf1a37b83` | MZ1: round/stage3 mul |
| `0x37a33af5` | MAGIC_8: round/stage3 OR-pair mul |
| `0x74ecaa8b` | Stage 5 fmix32 first mul (MAGIC_A) |
| `0xa3b2ce45` | Stage 5/6 fmix32 second mul (MAGIC_B) |
| `0x542cbd2b` | ADDER: (s0-channel) |
| `0x1baac857` | ADDER: (s1-channel) |
| `0x95ca2c45` | ADDER: (s2-channel) |
| `0x31ab4b27` | ADDER: (s3-channel) |
| `0x75ea0000` | Stage 2/3 OR-pair upper mul |
| `0xc8cf0000` | Stage 2/3 OR-pair upper mul |
| `0xee0c0000` | Stage 2/3 OR-pair upper mul |
| `0x4a950000` | Stage 4 MX2_pre |

### 反逆向发现

`0x2b838` 内部通过 ARM helper (PC 0x33xxx) **读取 libxyass.so 自身 ELF header**
(`\x7fELF` magic)，把二进制的 metadata 作为哈希输入的一部分。这意味着：
- 纯 Py 复写需要"打包" libxyass.so 的 ELF header bytes 作为 data dependency
- 不是算法不可知,而是算法**故意耦合 binary layout**

### 交付物

- `unicorn/py_signer/shield_mac16.py` — 生产可用 API
  - `mac16(key, msg) → 16B tag`
  - Unicorn 仅剩 `_opaque_setup` 一个函数
  - 6 个纯 Py 阶段经过 50/50 random + 35/35 edge-case 验证
- `scratch/ghidra_work/run_0x2b838.py` — 独立测试 harness
- `scratch/ghidra_work/run_intercept_v2.py` — shield_builder 端到端 Unicorn harness
