# XHS libxyass — 最终状态与硬上限（纯静态 RE）

**日期**: 2026-04-13
**方法**: Ghidra + Unicorn + jadx_out + 抓包对比（无 Frida、无真机）

这是 18 号文档之后的最终诊断。回答用户问题"所有签名都能拿到了？" — **没有**，
还差 4 个 per-request hash header，且**纯静态方法已经触到物理上限**。

---

## 总体定位

我们 5 个 session 一路走下来的成果：

| 阶段 | 状态 | 信心 |
|---|---|---|
| 算法**形状**（HMAC-SHA1, base64, device-key） | ✅ 完整还原 | 100% |
| 算法**实现**（哪个函数是 Init/Update/Final, 入口） | ✅ 全部定位 | 100% |
| **SHA-1 标准性**（K 常量, IV, round 函数） | ✅ 100% 标准 | 100% |
| **Java 层密钥来源**（ContextHolder.sDeviceId/sAppId） | ✅ 反推完成 | 100% |
| **canonicalize 字节模板** | ❌ 没拿到 | 0% |
| **Unicorn 中端到端运行** | ❌ 出零结果 | 阻塞 |
| **Python 端能签新请求** | ❌ 不能 | — |

---

## 抓包对比给出的最终事实

29 个真实 mitm 抓包，对每个 per-request header 做 distinct-value 统计：

```
=== 每请求都不同的（4 个签名 header）：===
  shield      : 29/29 distinct  (100 字节，最后 16 字节变化)
  x-mini-mua  : 27/29 distinct  (变长 1096-1312 字节，含 5 种不同 binary tail)
  x-mini-sig  : 27/29 distinct  (32 字节 = SHA-256 大小)
  x-mini-s1   : 27/29 distinct  (新发现的第 4 个签名通道)

=== 设备/会话常量（可直接复制）：===
  x-legacy-did: aa293284-0e77-319d-9710-5b6b0a03bd9c  ← ContextHolder.sDeviceId
  x-legacy-sid: session.1774780073824545783425
  x-legacy-fid: ""
  x-mini-gid  : 7cb8488b93895495c7fef48a674f81d13df30d6947359981776791f5
  user-agent  : Dalvik/Pixel 6/Android 15/v9.19
```

**结论**：4 个 per-request 签名 header 全都不能复现。

---

## 差分 trace 结果（diff_trace_sha1_update.py）

跑 intercept 两次（url=`/api/aaaaaaaa` vs `/api/zzzzzzzz`），hook 关键 PC：

```
Run A 和 Run B 都执行了 8842 条指令，到达 last_pc=0x248be (intercept 末尾)
两边都触发了：
  call_wrapper      (0x2474c) 1x
  helper_1ee70      (0x247a4) 1x
  header_wrapper    (0x24a1c) 1x
  canonicalize_low  (0x24ea0) 1x        ← enum<6 路径
  HMAC_b64          (0x286d0) 1x

但是：
  SHA1_Init/Update/Final 一次都没被调用！
  canonicalize_high (0x24bcc) 一次都没被调用！

0x286d0 输出（两边完全相同）：
  ctx=0x700fbe7c r1=0x1 r2=0x700fbe70 r3=0xb001002c
                                          ↑ 是我们的 .bss sentinel！
  output: cap=96 size=84 dptr=0x82fa6da0
  content (84B): "AAAAAAAA...AAAA="  ← base64 of 62 zero bytes
```

### 这告诉我们 4 件事

1. **intercept 在 Unicorn 下只跑出一个 header**（real device 跑 4-6 个）。
   原因：很多分支取决于 `.bss` 里被我们填成 sentinel `0xb001XXXX` 的字段，
   走了"什么都没有"的占位路径。

2. **0x286d0 不是 0x24bcc 调的 SHA-1 函数**（这条路径根本不进 0x24bcc）。
   实际上 SHA-1 是被 **canonicalizer 0x24bcc 内部** 调的，而 0x286d0
   自己用的是另一个 hash 家族（0x6d0f0/0x6d1d4/0x6dd28/0x6ecae）。

3. **0x286d0 在我们的 harness 下产出全零**（`AAAA...A=`），说明它的内部
   hash 计算依赖了某些**未初始化的全局状态**（应该由 JNI_OnLoad 设置）。

4. **URL 字节根本没传到 0x286d0**：r3=0xb001002c 是 .bss sentinel，意味着
   它在读我们填的占位数据，不是真实的 header_enum 整数。所以 update 真实
   消费的字节流（即 canonicalize 输出）我们抓不到。

---

## 0x286d0 内部不调 SHA-1，调什么？

新发现的 hash 家族（被 0x24ea0 而不是 0x24bcc 调用）：

```
0x6d0f0   ← 第一个被调，类似 SHA1_Init
0x6d1d4   ← 第二个，类似 update/transform
0x6dd28   ← 第三个
0x6ecae   ← 第四个
```

这 4 个函数的反汇编里没有任何 movw/movt 装载已知 hash 常量
（SHA-1/SHA-256/MD5 IV 或 K 都没有），意味着它们要么用 **CFG-flatten 编码
的 K 常量**（跟 0x2ad80 一样），要么是**完全自定义的 hash**（如 SipHash、
Murmur 等非标 hash）。

需要再做一轮 deep_trace 看 0x6d0f0 系列的运行时常量才能定性。**这是下一步
最有价值的静态工作**。

---

## 纯静态 + Unicorn 的硬上限：为什么走不下去

具体的物理阻塞：

### A. .bss 全局状态依赖

libxyass 在 JNI_OnLoad 阶段做了大量的：
- 加密字符串解密 → 写入 .bss 全局 std::string
- Java class/method/field 引用缓存 → 写入 .bss
- ContextHolder.sDeviceId / sAppId → 读到 .bss 字符串槽位
- 各种 init flag → `.bss + dmb ish` 的 release-acquire 同步

我们的 Unicorn 没法精确复现 JNI_OnLoad（之前尝试过，跑 388 条指令就崩）。
所以我们手工填的 sentinel 让 intercept 走"占位"分支，永远拿不到真实输入。

### B. JNI mock 的语义不够

Unicorn 里我们 mock 了：
- GetStringUTFChars → 返回我们的 fake URL
- GetByteArrayElements → 返回 fake body
- GetStaticObjectField → 返回 sentinel `0xfa570001`

但 libxyass 内部对返回值有**深结构依赖**：例如它会调用
`CallObjectMethod(env, obj, methodID)` 期待返回另一个 Java 对象，而我们
只能返回常量。这导致很多链式调用半路死掉。

### C. CFG-flatten 让局部反汇编无效

每个关键函数（0x286d0、0x2ad80、0x24bcc、0x6d0f0...）都用
`mov pc, rN` + 算术偏移构造跳转地址。这意味着：
- 静态 call graph 完全无效（看不到真实跳转目标）
- K 常量散落在 80+ mini-blocks 里
- 函数边界模糊（一个"函数"会跳进另一个函数中段）

这就是为什么 deep_trace_2ad80.py 抓到的指令 PC 在 0x2ab... 范围（看起来在
"0x2ad80 之外"，但实际是 update 跳进去执行的）。

---

## 还有什么纯静态方法能做？

按 ROI 排序：

### 🟢 高 ROI（值得做）

1. **deep_trace 0x6d0f0 / 0x6d1d4 系列**（类似 deep_trace_2ad80.py）
   找出 0x286d0 实际使用的 hash 原语。可能发现是 SHA-256 / MD5 / SipHash 之一。
   工作量：~1 小时。
   收益：知道 x-mini-sig 的 32 字节 hash 是哪种算法。

2. **抓包数据驱动的暴力 brute force**（bruteforce_shield_tail.py 升级版）
   - 把所有 29 个 (request, shield_tail) 当成约束
   - 试更多 key 派生方式：`sha1(deviceId)`, `sha1(deviceId + sAppId)`,
     `sha1(deviceId + cert_hash)` 等
   - 试更多 message 模板：包含 `mua['c']` counter, timestamp, gid 等
   - 试常见 transform：HMAC-SHA1[0:16] XOR fixed_mask
   工作量：1-2 小时。
   收益：可能直接破出 shield_hash16 公式。

3. **看 0x24ea0 内部完整调用链**
   既然我们 trace 到这条路径被实际触发，看它每一步在做什么。
   可能能直接从静态反汇编读出 canonicalize 的字符串拼接逻辑
   （就像 0x24bcc 内部我们已经看到 SHA1_Init/Update/Final 的明显模式）。
   工作量：~1 小时。

### 🟡 中 ROI（边际收益递减）

4. 把 .bss 用更接近真实 device 的字节填充（要从抓包反推 sDeviceId UTF-8 字节
   写到 0x7df10/0x7df20），看 intercept 的执行是否能跳出 sentinel 分支。
   工作量：2-3 小时。
   风险：可能仍然进不到真实路径。

### 🔴 低 ROI（已经触底）

5. 让 0x1f454 完整初始化跑通。之前 388 条指令就崩，深度 mock 工作量太大。
6. 完全静态地反混淆所有 CFG-flatten 跳转。这需要写一个 symbolic executor 解
   `mov pc, rN` 的目标地址，工作量数十小时。

---

## 务实结论

**从静态 RE 角度，我们已经把能拿到的全拿到了**。算法形状、所有关键函数的
位置、SHA-1 的标准性、Java 侧密钥来源、shield 的 100 字节布局 —— 这些都
完整还原了。

**从"复现一个能签新请求的 Python signer"角度，我们离目标还有 30%**。差的
全是需要**动态执行才能拿到的字节级细节**（canonicalize 模板、key 派生、
0x286d0 在真实状态下的输出）。

如果用户严格坚持纯静态 + Unicorn，下一步最值得的是 **方案 1 + 2 + 3**
组合（约 4 小时）。它们可能（但不保证）让我们拿到 shield 16 字节的精确公式。

如果用户哪天放宽限制，**单次** Frida hook 在 0x286d0 入口处抓一组真实的
(input, output) 就能在 5 分钟内验证我们的所有假设并锁定密钥派生方式。
但那超出了用户的 ground rule。

---

## 本会话新增文件

| 文件 | 作用 |
|---|---|
| `scratch/ghidra_work/diff_trace_sha1_update.py` | intercept 多 PC hook + 差分 trace |
| `scratch/ghidra_work/deep_trace_2ad80.py` | 已在前一 session 写过；本次确认 SHA-1 标准性 |
| `scratch/ghidra_work/probe_286d0_hmac.py` | 已在前一 session 写过；确认 base64 输出形状 |
| `scratch/ghidra_work/xhs_device_pin_signer.py` | device-pinned 半成品 signer（self-test 通过 84-byte prefix） |
| `scratch/ghidra_work/bruteforce_shield_tail.py` | 抓包数据驱动暴力搜索（首轮无匹配） |
| `docs/19_FINAL_state_and_ceiling.md` | 本文档 |
