# libtiny.so — 深度静态分析

**日期**: 2026-04-14
**目的**: 找出 `x-mini-sig` / `x-mini-s1` / `x-mini-mua` 的 native 签名算法

---

## 基本事实

| 属性 | 值 |
|---|---|
| 大小 | 6,030,820 字节 (6 MB) |
| 架构 | ARM 32-bit, ET_DYN |
| `.text` 段 | 5,267,808 字节 (~5 MB) |
| `.rodata` | 71,104 字节 |
| `.bss` | 49,168 字节 |
| `.init_array` | 336 字节(42 个构造函数) |
| 导出符号 | **仅 1 个**: `JNI_OnLoad @ 0xb22b5` |
| Ghidra 函数总数 | 4010 |
| 大于 1 KB 的函数 | 158 |

**对比**: libxyass 是 0.5 MB,只有 ~700 个函数。libtiny **大 12 倍,代码量大 6 倍**。

---

## Java 入口

[`com/xingin/tiny/internal/t.java`](../target/jadx_out/sources/com/xingin/tiny/internal/) — jadx 没有反编译出来,但 dexdump 显示:

```java
public class com.xingin.tiny.internal.t {
    // 字段
    public static Gson a;
    public static PackageInfo b;
    public static String c;
    // ... 还有更多

    // 关键方法 — NATIVE!
    public static native Object a(int method_id, Object[] args);
    // public static native Object b(int method_id, Object[] args);  (推断)
}
```

`access: 0x0189` = `PUBLIC STATIC VARARGS NATIVE` — **这是 native 方法,在 JNI_OnLoad 中通过 RegisterNatives 注册**。

Java 侧 `f.j(method, url, body)` → `d3.b(-1750991364, ...)` → `t.a(-1750991364, ...)` → libtiny 的 native dispatcher → switch by method_id → 各种 handler。

---

## 字符串混淆(同 libxyass)

libtiny 中**所有**关键 JNI 字符串都被 XOR 加密:

| 字符串 | 状态 |
|---|---|
| `(I[Ljava/lang/Object;)Ljava/lang/Object;`(t.a 签名) | ❌ 不存在为字面量 |
| `com/xingin/tiny/internal/t`(class 名) | ❌ 不存在 |
| `RegisterNatives`(JNI 函数名) | ❌ 不存在(也不是 imported symbol) |
| `(Ljava/lang/String` | ✅ 在 .rodata |
| `Object;)` | ✅ 在 .rodata |

字符串运行时通过 `c7.f140556a.a(encrypted, key)` 解密(同 ega.f.java 的 pattern)。

---

## Dispatch ID 也被混淆

14 个已知的 dispatch ID 在 libtiny 二进制中**全部 0 hits** 作为 32-bit 字面量:

| ID | hex | 用途 |
|---|---|---|
| `1897791419` | `0x711dffbb` | d3.a generic |
| `-378830707` | `0xe96b808d` | x-mini-gid (`d3.b()`) |
| `-1750991364` | `0x97a1fdfc` | **主签名** (sig/s1/mua via f.j) |
| `617278119` | `0x24caeaa7` | byte transform |
| `1268781800` | `0x4ba012e8` | file timing |
| `704287623` | `0x29fa9387` | shutdown |
| ...(共 14 个) | | |

也不是 movw/movt 16-bit 半值相邻存储(检查了 lo/hi 的相邻位置)。

→ Dispatch ID 在运行时**通过 XOR/算术从 .bss/.rodata 派生**,跟 libxyass 同样的混淆模式。

---

## 候选 dispatch 函数

按大小排序的 Top 10:

| 函数 | 大小 | 说明 |
|---|---|---|
| `FUN_00484540` | 13,450 字节 | **最可能是 dispatch 函数** |
| `FUN_0049f070` | 8,770 |  |
| `FUN_004a1ea8` | 7,036 |  |
| `FUN_003a1d80` | 6,024 |  |
| `FUN_0009d0d8` | 4,926 |  |
| `FUN_0019a340` | 4,512 |  |
| `FUN_00322ccc` | 4,460 |  |
| `FUN_003007bc` | 4,384 |  |
| `FUN_001c2374` | 4,312 |  |
| `FUN_0019b970` | 4,294 |  |

但 **没有一个**包含 14 个 dispatch ID 中的任何一个作为 ARM immediate。

---

## Ghidra 反编译的失败

`FUN_00484540` (13 KB) 的 Ghidra 反编译输出:

```c
void FUN_00484540(int param_1, int param_2, ...)
{
  // 100+ undefined locals
  undefined4 uVar1, uVar2, uVar3, ...
  uint *******__ptr;
  code *UNRECOVERED_JUMPTABLE_01;
  // 整个函数体 8000+ 字符,完全乱码,
  // 中间有多个 "WARNING: Treating indirect jump as call"
  // 和 "Could not recover jumptable" 警告
}
```

**Ghidra 完全无法跟踪 CFG-flatten dispatcher**(`mov pc, rN` 的目标在运行时计算)。这跟 libxyass 同样的问题,但在 libtiny 上更严重(函数更大、更复杂)。

`JNI_OnLoad` 的反编译同样失败:

```c
void JNI_OnLoad(void) {
  code *UNRECOVERED_JUMPTABLE;
  UNRECOVERED_JUMPTABLE = (code *)(*(int *)(DAT_000c2678 + 0xc22e2) + -0x3e5ad44);
  /* WARNING: Could not recover jumptable at 0x000c2318. Too many branches */
  /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(...);
  return;
}
```

---

## Unicorn 模拟也失败

我尝试了 `scratch/ghidra_work/emu_libtiny_jni.py` —— 把 libxyass 的 `emu_v2.py` 适配到 libtiny。结果:

```
Starting JNI_OnLoad emulation @ 0xb22b5
    GetEnv → ENV_BASE
    env[219/env[219]] r1=0x701fbfc8 r2=0x400006d9 r3=0x1
  invalid @ 0x1bc skip 2
  ... (multiple invalid instructions)
err @ 0x5b78c: Unhandled CPU exception (UC_ERR_EXCEPTION)
=== 0 RegisterNatives calls ===
```

**JNI_OnLoad 在执行 7 条指令后就 crash**。原因:
- libtiny 的 JNI_OnLoad 比 libxyass 复杂得多
- 它先调用 `env[219]` (FindClass 或 GetClass 系列),然后访问字段 — 我的 stub 不够 detailed
- 中途遇到无效指令(可能是 Ghidra 错误识别成 Thumb 而它实际是 ARM 模式切换)

**给一个 6 MB 库写完整 Unicorn JNI 模拟器是几天的工作量**,且容易出错。

---

## 哪些已知 vs 未知

### ✅ 已知

- libtiny 通过 RegisterNatives 注册 `t.a(int, Object[])` native 方法
- Java 调用 `t.a(method_id, args)` → 进 libtiny dispatcher
- Dispatcher 根据 method_id 走 switch,每个 case 是一个 handler
- 14 个已知 method_id 对应 14 个不同功能(主签名、gid、字节变换等)
- libtiny 用相同的 XOR 字符串混淆 + CFG-flatten 控制流混淆

### ❌ 未知

- 14 个 dispatch ID 各自对应的 handler 函数地址
- 每个 handler 内部的实际算法
- `_hmac` / `RSA` / `KeyStore` 等加密原语在哪个地址、用什么方式调用
- `x-mini-mua` 的 RSA 签名是不是真的走 Android KeyStore(我们假设的),还是用其他方式
- `x-mini-sig` / `x-mini-s1` 的具体哈希算法(SHA-256 假设来自 doc/18 的猜测)

---

## 结论

**libtiny 静态分析的天花板已经到了**,跟 libxyass 一样:
- 字符串运行时解密
- Dispatch ID 运行时算出
- CFG-flatten 让 Ghidra 反编译完全失效
- 单个函数 13 KB,手工反汇编需要数天甚至数周

唯一能继续推进的路径是 **动态 hook**(给另一个窗口的请求):

### 最小数据需求(给另一个窗口)

```c
// Hook libtiny's RegisterNatives call inside JNI_OnLoad
// Dump the JNINativeMethod array entries:
for each entry:
    name: "a" / "b" / others  
    sig:  "(I[Ljava/lang/Object;)Ljava/lang/Object;" / 其他
    fn:   <实际函数地址>
```

→ **拿到 t.a 的 native 函数地址**(估计是 `FUN_00484540` 或类似的大函数)

然后:

```c
// Hook the t.a function entry, dump:
//   - method_id (third arg)
//   - args (fourth arg, Object[] decoded)
// for each call
```

→ **拿到 14 个 method_id 各自对应实际调用模式 + handler 入口**

最后:

```c
// Hook each handler function (e.g., the one for -1750991364 main signing)
// Dump args + return value + intermediate state
```

→ **拿到 sig/s1 的具体哈希实现**

---

## 现状

- **Java 侧**: 10/14 头完整 Py 复写
- **libxyass 侧 (shield)**: ❌ 卡在 inner_hash CFG-flatten
- **libtiny 侧 (sig/s1/mua)**: ❌ 卡在 dispatch table runtime resolution
- **mua RSA**: ❌ 物理不可纯离线(KeyStore TEE)

**没有动态 hook 数据,4 个 native 头 0/4 可生成。**
**有动态 hook 数据,3/4 可生成**(mua 走 replay)。
