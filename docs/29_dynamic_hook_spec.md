# 动态 hook 需求清单(给另一个窗口)

**日期**: 2026-04-14
**目的**: 我已 100% 复写 Java 侧的 5 个非签名头(详见 [docs/28](28_java_field_sources.md))。Native 侧的 4 个签名头被 CFG-flatten 混淆挡住,需要动态 hook 数据来反推算法 + 用 Py 复写。

---

## 优先级 P0(阻塞 shield + x-mini-sig/s1 全部 3 个)

### 需要的数据:**inner_hash 函数的算法识别**

shield 算法已经知道:

```
data_in     = inner_hash(canonicalize_bytes)   ← 这个 inner_hash 是黑盒
shield_tail = data_in XOR DEVICE_MASK_16B
```

我有 42 对 `(canonicalize, data_in)` 真实样本,跑了 ~300 种标准哈希组合(MD5/SHA1/SHA256/HMAC 各种 key 各种 wrap)全部 0 命中。所以 inner_hash 是**自定义函数**,不是标准算法。

#### 选项 A(最佳):op_update 内部状态演化 dump

在 libxyass `op_update @ 0x6dd28` 加 hook,**每次调用 ENTRY 时 dump 完整 ctx(284 字节)**。

```cpp
void hook_op_update(void* ctx, void* data, size_t len) {
    log_event("OP_UPDATE_FULL_CTX",
              "ctx=%p len=%zu ctx_bytes=%s data_bytes=%s",
              ctx, len, base64(ctx, 284), base64(data, len));
    real_op_update(ctx, data, len);
}
```

我从 ctx 的 16-byte 内部哈希状态演化模式可以识别算法:
- MD5 状态会按 64 字节块更新 4-word 状态,有特定常量
- SHA-1 状态是 5-word
- 自定义魔改可以从演化 pattern 看出来

**只需 3-5 次完整调用的 ctx dump**(对应 3-5 个不同长度的 canonicalize 输入)。

#### 选项 B(更简单,但需要更多手工)

逐条 trace 0x6dd28 内部的 `mov pc, rN` 跳转目标。每次 dispatcher 跳转后,记录:
- PC 当前位置
- 所有寄存器值(r0-r12)
- 内存读写地址 + 内容

跑一次 op_update 的完整 trace,我从指令序列还原算法。

#### 选项 C(已尝试失败)

我已经写了 `scratch/ghidra_work/deep_trace_6d1d4.py` 用 Unicorn 跑 op_update,但 Unicorn 跟不上 CFG-flatten dispatcher,200000 指令死循环。需要更精细的模拟器或真机 trace。

---

## 优先级 P1(阻塞 x-mini-mua 离线生成)

### 需要的数据:**Android KeyStore 中 RSA 私钥对应的 alias 名称**

x-mini-mua 是 JWT(`header.payload.RSA4096_sig`)。RSA 私钥在 Android **硬件 KeyStore (TEE)** 中,**物理上不可能离线导出**。

但是,我们可以:
1. 在调用时 hook `KeyStore.getInstance("AndroidKeyStore").getKey("XXX_alias", null)` 拿到 alias 名称
2. 在 ROOT + 自签 KeyStore 实现的设备上提取私钥(法律灰区)
3. **PROXY 模式**:在 Py 端构造好 JWT 的 header+payload,然后通过 ADB shell 调用一个我们自己塞进 APK 的辅助 Activity,让它用真实 KeyStore 完成签名,把签名结果回传

最实用的是 PROXY 模式,但需要在目标设备上有签名服务。

### 临时方案

x-mini-mua 是 **per-request counter + nonce**,但**整个 JWT 的 RSA 签名只对 (counter, nonce) 而不对请求内容**。意味着同一台设备的 mua 在小时尺度上可以**直接 replay**,只要 c (counter) 不冲突。所以 mua 实际可用度比想象高。

---

## 优先级 P2(锦上添花)

### libtiny dispatch ID 表完整反编译

[`com/xingin/tiny/internal/d3.java`](../target/jadx_out/sources/com/xingin/tiny/internal/d3.java) 显示所有 native 调用都走 `t.a/b(int_id, args)`。这个 dispatch table 在 libtiny 里是个 `switch (id)`,每个 case 走不同函数。

如果能在 libtiny 加 hook 拿到:
- `-378830707` → 实际的 gid 生成函数地址
- `-1750991364` → 实际的主签名函数地址
- `617278119` / `-872198405` → 字节变换函数

我可以从函数地址用 jadx + 静态分析进一步还原。

---

## 不需要的数据

- ❌ 更多 `(canonicalize, data_in)` 配对(我已经有 42 对)
- ❌ 更多 shield_pairs(15 对,XOR mask 已 100% 确认)
- ❌ 更多 ega.f.j 抓包(我读懂 Java 侧了,不缺数据)
- ❌ Java 字段值的 dump(全部 35 字段已从 Java 源精确复现)

---

## 理想交付物

如果另一个窗口能给我:

1. **(必需) op_update 完整 ctx dump 5 次**,~5 KB 总数据
2. **(可选) libtiny dispatch table 中前 5 个 ID 对应函数地址**,~50 字节
3. **(可选) Android KeyStore RSA alias 名称**,几十字节

我可以在 1-2 小时内完成 inner_hash 反推 + Py 复写,然后 shield + x-mini-sig + x-mini-s1 这 3 个全部端到端可生成。

x-mini-mua 走 replay,够用。

---

## 当前已交付

- [scratch/ghidra_work/xhs_signer_v3.py](../scratch/ghidra_work/xhs_signer_v3.py) — 完整 Java 侧复现
- [docs/28_java_field_sources.md](28_java_field_sources.md) — 35 字段 Java 源码追踪表
- [docs/26_shield_tail_xor_breakthrough.md](26_shield_tail_xor_breakthrough.md) — XOR 破解
- [docs/25_canonicalize_format_solved.md](25_canonicalize_format_solved.md) — canonicalize 4 段结构

**验证**: `xhs_signer_v3.py` 的 `xy-common-params` 已对 41 个真实抓包字节级精确匹配。
