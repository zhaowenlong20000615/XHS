# 2026-04-18 EOD3 cptr bucket 分析 — 172B gap 根因

## 突破性发现 (用户直觉驱动)

用户: "肯定有本地数据 + 服务端响应一起签名"。重新审视所有抓包(尤其 cptr_usertrace_1776505151.log)发现:

### 真机 cptr 结构 (XhsHttpInterceptor.cPtr field)

```
+0x000: ".main" SSO (12 字节)
+0x00c: "main_hmac" SSO (12 字节)
+0x018: heap pointer to main_hmac blob (非常 fresh 时=0, 0.3s 后被 406 push 填)
+0x020: ZEROS
+0x040: 0x0004c105 0x000005b2   ← bucket 1 counter (varint or event_id+counter)
+0x060: 0x94d5caf0                 ← bucket 1 heap pointer
+0x078: 4 heap pointers (指 libtiny 内部函数)
+0x0a0: ZEROS
+0x0a8: 0x0010 92c6 0x00040581 0x6b44   ← bucket 2
+0x0c8: 3 heap pointers (0x7d85xxxx 范围)
+0x108: 0x00040581 0xf5c2          ← bucket 3
+0x168: 0x00040581 0x9a9b          ← bucket 4
+0x1c8: 0x00040581 0xd214          ← bucket 5
```

**首次 sign 前 cptr 已有 5 个 bucket 结构**。

### 我们 unidbg cptr

```
+0x000: ".main" SSO
+0x00c: "main_hmac" SSO
+0x018: 0x40276240  ← 我们指向一个空的东西(pointer 有, 但指向的内容是 0)
+0x020-0x1ff: **全部 ZEROS**
```

**我们一个 bucket 都没分配**。

## 如何 populate bucket?

真机 fresh install 首次 sign 前的**第一个 cmd 是 d7.a (cmd 1140071423) 调用 46 次**。每个 d7.a:
- args = (Long runtime_handle, byte[N] event_payload, byte[2] category)
- 内部逻辑: 用 runtime_handle 作为 object key, 若 cptr 没 bucket 则分配, 否则 update counter
- return null (metric sink, 无返回值)

**46 次 d7.a → ~5-6 unique buckets → cptr 头 512B 填满 → mua 序列化包含 bucket → +172B**

### unidbg 中 d7.a crash 原因

docs/54 已确认 long_arg 是运行时生成(非 ELF 硬编码), 每次进程 startup 不同。libtiny 内部用 Long 作为 key 查 STL 容器 (map<jlong, Bucket*>)。查找逻辑应该是 OK 的, 但可能内部**第一次 d7.a** 需要先**静态初始化全局 map 对象**。

我们 unidbg 调 d7.a 立即 UC_ERR_FETCH_UNMAPPED crash — 可能是那个全局 map 的 vtable 指针没 init。

## 解法候选

### 方案 A: 修 d7.a crash 根因 (理想黑盒)
ARM disasm d7.a 分发函数, 找内部依赖的 vtable / global object / function pointer 表, 补齐 unidbg 内存中对应的字节。

**成本**: 1-2 周深 ARM 反汇编  
**产出**: 纯黑盒, 46 次 d7.a 自然 populate cptr

### 方案 B: 直接 hex-patch cptr (半黑盒 shortcut)
从真机 cptr dump 提 5 个 bucket 的结构模板 (值可以占位), 在 XhsCombinedSigner initialize() 末尾 mem_write 到 cptr+0x40 起的位置。libtiny 序列化 mua 时会 dump 这些 buckets, mua 增长。

**成本**: 1-2 小时  
**风险**: 伪造 bucket 内容可能被 libtiny 内部一致性检查否决
**产出**: 可能直接让 mua 从 1165B → 1337B

### 方案 C: 钓真机首屏 46 次 d7.a 的完整 hex (args), 在 unidbg 里**跳过真实 d7.a 调用**, 直接 write cptr 字节
最实用。现有 docs/54 已抓 50 次 d7.a 完整 hex, 我们能 offline reconstruct 真机 cptr 每 bucket 字节, 然后 hex-patch。

**成本**: 30 分钟  
**可行性**: 最高, 基于已有真机数据 reverse 实现

## 我的建议

**走 C (hex patch cptr)**。步骤:
1. 读 cptr_usertrace 解析真机 cptr 5 bucket 布局
2. 写 PatchCptrBucket() 方法在 initialize() 末尾 mem_write 到 cptr+0x40
3. 跑 probe 看 mua len → 接近 1337B 即证实
4. 跑 live test 看 3/5 是否破

失败风险: 伪造的 heap pointer (bucket 内指向 libtiny 某函数的) 在我们 unidbg 里无效, mua 序列化时可能 crash。解法: 要么只 patch 计数器部分(不碰指针), 要么 patch 指针指向我们 unidbg 里 libtiny 对应地址(可能 offset 一致)。

## 下一步

等 user 确认走 C 后立即动手。
