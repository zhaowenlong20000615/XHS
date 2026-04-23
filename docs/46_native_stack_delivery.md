# docs/46 — docs/45 交付:main_hmac putString 的 native stack

**Responds to**: docs/45
**Artifacts**:
- `lsposed/xhs-capture/jni/src/native_stack.c`
- `lsposed/xhs-capture/src/com/xhs/capture/NativeStack.java`
- `lsposed/xhs-capture/src/com/xhs/capture/XhsCapture.java` (putString hook 扩展)
- `scratch/persistent_survey/main_hmac_native_stack.log` (6 次 capture,17 KB)
- `scratch/persistent_survey/crash_tombstone_full.log` (tombstone 回溯,264 行)

---

## TL;DR — 给 unidbg 的 3 个 PC

**libxyass.so 里 main_hmac 写入路径的关键 PC**:

| PC                 | 含义                                         | 来源                |
|--------------------|----------------------------------------------|---------------------|
| `libxyass+0x1ee19` | `env->CallObjectMethodV(editor, putString, key, value)` 调用点 | tombstone #15       |
| `libxyass+0x1ee1b` | 上面那条 `blx` 的返回地址(PC+2)                | stack scan (6/6 次) |
| `libxyass+0x2525d` | 调用前面函数的 caller 的返回地址               | stack scan (6/6 次) |
| `libxyass+0x2525b` | caller 的 `blx` 指令位置                     | tombstone #16       |
| `libxyass+0x24851` | 更外层 caller (大概率是 `Native.intercept` 主体) | tombstone #17       |

**libxyass BuildId**: `dd6f657739d9a6212bd27e4bc895a79d3c52fc57`
(用来校验 unidbg 里拉的 so 和真机版本一致)

这 3~5 个 PC 把 docs/45 的反汇编窗口从"扫整条 Native.intercept (几千条 Thumb)"缩到"看 `libxyass+0x1ee00..0x24900` 周围 50 条指令"。

---

## 1. 实施经过 & 踩到的坑

### 1.1 `_Unwind_Backtrace` 在这条路径上不能跨 JNI 边界

按 docs/45 推荐用 `_Unwind_Backtrace` 写了 `Java_com_xhs_capture_NativeStack_capture`。实际效果:
- 只返 1 帧 (我们自己 libnative_stack 里的 PC)
- 之后或连续重复同一 PC 29 次,或直接 stop

原因:LSPosed 的 Java 端 `beforeHookedMethod` 回调跨过了 ART 的 JNI 桥 + art_quick_invoke_stub。这些 ART 生成的代码**没有 ARM EHABI `.ARM.exidx` 表**,libgcc unwinder 到这里就走不了。

### 1.2 `/proc/self/maps` 合并同名 .so 会误报

第一版把同名 `.so` 的多个 r-xp 段按 basename 合并成一条 `[lo, hi]`。问题:
- **libheif.so** 同时存在于 app (`/data/app/.../libheif.so`) 和系统 (`/system/lib/libheif.so`),地址相差 ~2 GB
- 合并后 libheif.so = `[0x59baa000, 0xeb6c9000]`,把 libart 的 `0xe72b6eee` 也当成 libheif+0x8d70ceee

修复:**每条 r-xp 独立保留**,按 `pc ∈ [lo, hi)` 严格逐条比对。

### 1.3 LSPosed 的 Java hook 回调栈是"另一块栈"

第一版 `scanStack` 从 `&sp_marker` 往上扫 64 KB,**全是 0**。对比 `pthread_getattr_np` 拿到的 pthread 栈区间,发现:

| 数据点        | 值                                                   |
|---------------|------------------------------------------------------|
| pthread 栈   | `0x549a3000..0x54aa7d70` (1043 KB)                  |
| `&sp_marker` | `0x54a97124` (在 pthread 栈区间内)                   |
| 扫描到的 libart 地址 | 出现在 `stack+0x0e7714..0x0eb32c` 一带         |
| 扫描到的 libxyass 地址 | 出现在 `stack+0x102500..0x103000` 一带       |

也就是说 `&sp_marker` **是**在 pthread 真栈上,但它在栈底附近(最新帧),我们要找的 libxyass 帧在 **偏上 ~1 MB** 的位置 —— 原本只扫 8 KB 根本够不到。

修复:新增 `scanThreadStack + readRange`,先通过 `pthread_getattr_np + pthread_attr_getstack` 拿到栈边界,再**分 256 KB chunk 读完整条 pthread 栈**,筛选 `libxyass / libtiny` 地址。

### 1.4 Guard page 导致进程崩溃

`readRange` 第一版没容错,扫到 pthread stack guard page 时直接 `SIGSEGV` 崩 xhs 进程(反复崩了 3 次,tombstone 都存在 `crash_tombstone_full.log`)。

**但这个崩溃反而给了我们最精确的数据 —— kernel 的 tombstone unwinder 可以跨 JNI 边界(用 eh_frame/exidx + CFI),给出了完整 33 帧栈**,包括:
```
#14 libart.so  art::JNI<false>::CallObjectMethodV + 494
#15 libxyass.so  pc=0x0001ee19   ← 调用 CallObjectMethodV 的指令
#16 libxyass.so  pc=0x0002525b   ← 上一级
#17 libxyass.so  pc=0x00024851   ← 更外层
#18 art_jni_trampoline
...
#20 com.xingin.shield.http.XhsHttpInterceptor.intercept
```

这就是 docs/45 TL;DR 说的"native PC 栈"。

**稳定性修复**:给 `readRange` 装了线程本地的 `sigsetjmp` + `SIGSEGV` 处理器,碰到 guard page 就 longjmp 回来截断读取,返回已读内容,不再崩进程。

### 1.5 libart 噪声 vs libxyass 信号

pthread 栈 1 MB 里大约 800+ 个 libart 地址,libxyass 只有 3 个。原本 filter 放了 `libart.so+`,前 150 hits 全是 libart,**还没扫到 libxyass 偏移就被截断了**。

修复:scan pass 只保留 `libxyass / libtiny`;libart context 留给 `_Unwind_Backtrace` pass。

---

## 2. 最终数据(6 次 capture 的交叉验证)

所有 6 次 `putString("main_hmac", ...)` 触发点都看到这 3 个 libxyass PC **字节精确一致**:

```
capture #1 thread=sky1   stack+0x1025cc libxyass+0x1edf9
capture #1              stack+0x1025e4 libxyass+0x1ee1b
capture #1              stack+0x102600 libxyass+0x2525d
capture #2 thread=sky4   stack+0x1025cc libxyass+0x1edf9
capture #2              stack+0x1025e4 libxyass+0x1ee1b
capture #2              stack+0x102600 libxyass+0x2525d
... (×6)
```

**注意偏移差**:scan 给的是"栈上的 **return address**"(即 `bl/blx` 之后的下一条指令),tombstone 给的是"**调用指令本身**",差 2~4 字节(Thumb 指令长度)。unidbg 反汇编时**往回看 1 条 32-bit / 2 条 16-bit Thumb 指令**就能定位 `blx` / `bl` 本身。

### 2.1 反汇编锚点 (给 unidbg 侧)

```
libxyass.so BuildId: dd6f657739d9a6212bd27e4bc895a79d3c52fc57

★ 关键锚点 1: +0x1ee19 (tombstone) ≈ +0x1ee1b (scan return addr)
   预期指令: blx  <libart::CallObjectMethodV>  (JNI env 调 putString)
   反汇编范围: 0x1edfc .. 0x1ee40 看入口 + 调用序列

★ 关键锚点 2: +0x2525b (tombstone) ≈ +0x2525d (scan return addr)
   预期指令: blx  <libxyass+0x1edf9 函数>
   反汇编范围: 0x25200 .. 0x25280

★ 关键锚点 3: +0x24851 (仅 tombstone)
   预期指令: bl   <libxyass+0x252xx 函数>
   反汇编范围: 0x24800 .. 0x24880 — 这是 derive 分支 **if** 成立后调的 setter

推论:
   0x24851 -> 0x2525b -> 0x1ee19 -> art_CallObjectMethodV -> putString(Java)
   也就是 "3 层 libxyass 函数链 -> 一次 JNI 调用 -> 写入 SP"
```

### 2.2 派生的常数线索

两个偶然入 scan 网的 libxyass/libtiny 地址,可能是派生过程里的函数指针或 return address:
- `libxyass+0x6e6cc` (thread=sky5)
- `libxyass+0x200d9` (thread=sky4)
- `libtiny.so+0x1ed6f`, `+0x18af0`, `+0x22a508`, `+0x42f250` 等

这几个**不是**putString 路径必经节点,可能是同时运行的别的 intercept 请求的残留 LR,低信号。

---

## 3. Java stack (辅证,同 docs/42)

每次 putString 的 Java 侧栈都一致:

```
com.xingin.shield.http.Native.intercept(Native)   ← JNI 入口
com.xingin.shield.http.XhsHttpInterceptor.intercept(SourceFile:8)
  -> RealInterceptorChain.proceed
  -> qba.a.intercept (SourceFile:28-29)
  -> RealInterceptorChain.proceed
  -> lba.o.intercept (SourceFile:15)
  -> ...
```

即 putString 发生在 Native.intercept 内部,**不是**Application.onCreate 的 bootstrap。这和 docs/43 的结论一致。

---

## 4. unidbg 侧的下一步(干线 1)

1. 拉 libxyass.so(BuildId `dd6f6577...`)到 Ghidra,定位函数头:
   - func containing 0x1ee19  (最里层 — JNI 调 putString)
   - func containing 0x2525b  (中层)
   - func containing 0x24851  (外层 — 大概率包含 derive 分支的 if 判断)
2. 对 `func @ 0x24800` 周围逐条看 cmp/bne/beq,找 derive gate
3. gate 的条件追到某个 `blx <env_offset>` JNI 调用,对应 `env->CallXxxMethodV`
4. 在 unidbg 里补对应 JNI stub **返真实值**(参考现有 `PACKAGE_VERSION_CODE` / `signatureHashCode` / `MediaDrm` stub 的做法)
5. rerun — 如果 gate 过了,native 自己调 putString,spMap hook 自动捕获 main_hmac
6. 删除 `XhsCombinedSigner.MAIN_HMAC_VALUE` 硬编码

---

## 5. 交付清单

```
lsposed/xhs-capture/
  jni/src/native_stack.c                  (~170 行,含 _Unwind_Backtrace + pthread 栈扫描 + SIGSEGV 保护)
  jni/CMakeLists.txt                      (+1 target: native_stack)
  src/com/xhs/capture/NativeStack.java    (Java 绑定 4 个 native 方法)
  src/com/xhs/capture/XhsCapture.java     (putString hook 扩展:_Unwind + pthread 栈扫描 + maps 解析)
  build/xhs-capture.apk                   (含 libnative_stack.so ~40 KB)

scratch/persistent_survey/
  main_hmac_native_stack.log              ★ 核心交付 (17 KB, 6 次 capture)
  crash_tombstone_full.log                补充 (264 行, 包含最精确的 3 个 libxyass PC)

docs/
  46_native_stack_delivery.md             本文档
```

---

## 6. 经验总结 (下次再干类似事能少走弯路)

| 坑                                     | 下次直接                                                     |
|----------------------------------------|--------------------------------------------------------------|
| `_Unwind_Backtrace` 跨 JNI 边界失败    | 直接用 pthread 栈全扫,别依赖 unwinder                       |
| `/proc/self/maps` 同名 .so 合并        | 每个 r-xp 段独立,用 `lo + fileOff` 算 offset,匹配 Ghidra    |
| LSPosed hook 栈分片(看似 0)          | 用 `pthread_getattr_np` 找真栈边界,扫整条而不是 `&local_var` |
| guard page 崩                          | 读前装 `sigsetjmp + SIGSEGV handler`,崩了 longjmp 回来       |
| libart 噪声淹没 libxyass               | 扫描 filter **默认排除 libart**,只看业务 .so                |
| tombstone 是免费的精确 unwinder        | 有时**故意**触发可控 crash,tombstone 就是黄金               |

---

## 7. 一句话向上汇报

**docs/45 完成 —— putString("main_hmac", ...) 的 native 调用链收敛到 libxyass+0x1ee19 / +0x2525b / +0x24851 三个 PC,跨 6 次 capture 稳定一致。unidbg 侧反汇编这 200 字节窗口即可找到 derive gate,补对应 JNI stub 后 main_hmac 硬编码可删。**
