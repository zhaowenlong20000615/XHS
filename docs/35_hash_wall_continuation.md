# Hash 破解接力点 (2026-04-16)

**状态**: Unicorn 黑盒 canonicalize **6/6 字节级通过真机样本**;shield hash 数值差异是唯一阻碍端点验签通过。

## 当前已知事实

### 结构层 (已完成)
- `unicorn/sign.py` 的 4-hook pipeline 正确: gate@0x24f06 + capture@0x6dd28 + force_eof@0x25024 + inject@0x25042
- `unicorn/java_headers.py` 35 字段 HashMap bucket(64) byte-exact
- `scratch/test_canonicalize_byte_exact.py` 回归守卫 6/6 通过
- `XhsIdentity` 完整 override 面 (9 个 per-session 字段)

### Hash 层 (未完成)
- libxyass op_update@0x6dd28 是 **156 字节 C++ vtable dispatcher** (不是 hash 本身)
- 真实 hash 在 vtable 下一层,通过 `*(ctx+0x44)` → inner → `[+4]=data_buffer_with_vtable` → `[+0xc]=method_ptr` 调用
- 我们 emu 中 `*(ctx+0x44)[+0] = 0`,`cbz` short-circuits,真 hash **永远没跑**
- **hash 是 MD5 变种 (不是 SHA-1!)** —— Frida 标签误导
- **MD5 T-table 在 libxyass+0x79418**,全 256 字节精准匹配标准 sin 常量
- 48 对 Frida `(canon, 16B digest)` 样本 + 18 种标准构造 (plain / length-ext / HMAC / custom-IV LE+BE) = **0/48 命中**
- 结论: MD5 with 非标准 IV / byte-mixer pre-transform / 或 round 变种,至少其中一个

## 下一轮具体路径 (Path A — Unicorn 黑盒)

**目标**: 找到 MD5 compress 函数入口,用 Unicorn `_call` 子函数模式调它,拿真 hash。

### 步骤 1: 找 MD5 compress 函数入口 (预计 30-60 分钟)

T-table 在 .text 内的 0x79418,说明它是一个函数内部的 literal pool。能 PC-relative 加载它的代码必须在 ~4KB 范围内 (0x78000..0x7a500)。

但 OLLVM CFG-flatten 用 `ldr rN, [pc, #X]; add rN, pc` + `movw/movt; add rN, baseReg` 混合模式,linear disasm 找不到。

推荐做法:
1. **Ghidra full auto-analysis** 跑一次 libxyass (需要 `-process libxyass.so` **不加** `-noanalysis`), 10-15 分钟
2. 用修好的 `FindXrefsToAddr.java` 扫 0x79418 的所有 xref
3. 每个 xref 的 from address 所在函数就是 MD5 compress 候选

备选: 用 Unicorn **暴力 call** —— 在 0x78000..0x7a500 每 4 字节对齐地址尝试调用一次,hook MEM_READ on 0x79418..+0x100, 命中就是入口。~2500 次 emu_start 调用,估计 2-3 分钟。

### 步骤 2: 验证找到的函数是 MD5 compress

标准调用约定假设 `compress(state, block)` 或 `compress(state, data, len)`:
```python
# Pure-Python test: initialize a 16-byte state with MD5 IV, feed a test block,
# compare against hashlib.md5(test_block).digest()
state = bytes.fromhex('0123456789abcdeffedcba9876543210')  # standard MD5 IV
block = b'The quick brown fox jumps over the lazy dog' + b'\x00' * 21  # 64B
signer._shield._call(uc, compress_fn_addr | 1, (state_addr, block_addr, 64))
# Read state_addr back and compare to hashlib.md5(block).digest()
```

如果不匹配 → IV/round 被魔改;此时从 ctx_pre 里的 16 字节取自定义 IV 重试,或者观察字节差异规律。

### 步骤 3: 集成到 sign.py 的第 4 个 hook

当前第 4 个 hook 在 0x25042 注入 `hashlib.sha1(captured)[:16]`。替换为:
1. 在 Unicorn 子空间分配一个 state buffer (16B MD5 state)
2. 初始化 state (标准 IV 或从 ctx_pre 取)
3. `signer._shield._call(uc, compress_fn, (state, captured_canon, len))`
4. 读 state 作为 hash 输出,inject 到 r4 指向的 output buffer

### 步骤 4: 用 Frida pairs 回归验证

对 48 对样本中每一个:
1. 构造匹配的 XhsIdentity (用 `test_canonicalize_byte_exact.py` 那套 override 机制)
2. sign() 产出 shield-legacy
3. base64 decode 末尾 16 字节,和 `hmac_b64_input_hex XOR DEVICE_MASK` 对比
4. 目标: 48/48 精准

## Path B 备选 (如 Path A 卡住)

### ShieldCacheSigner 产品化

已存在 `unicorn/shield_cache_signer.py`,48 个 cached pair。对于**回放旧请求**场景,可以 sign 后 lookup 产出 byte-exact shield。**不能**对新请求用 —— t 变化导致 canonicalize 不匹配。

实用场景:
- 测试服务端是否只校验 shield 格式而不校验时间戳 → 回放一次 cached 请求,看 202x 年现在是否仍然 accept
- 如果 accept → 发现服务端"宽松"端点,今天的 signer 就能工作
- 如果全部 reject → 确认必须 path A

## 当前回归测试快照

`scratch/test_canonicalize_byte_exact.py` — **6/6 Frida samples byte-exact**

| # | 方法 | 路径 | canon 长度 |
|---|---|---|---|
| 0 | GET | /api/sns/v1/tag/reobpage | 937 ✓ |
| 1 | GET | /api/sns/v6/message/detect | 929 ✓ |
| 2 | GET | /api/sns/v6/homefeed/categories | 968 ✓ |
| 3 | POST | /api/push/badge/clear_v2 | 978 ✓ |
| 4 | POST | /api/im/v2/messages/unread (JSON body) | 1069 ✓ |
| 5 | POST | /api/sns/v1/paddles/pull_configs (form body) | 1007 ✓ |

这个不能退化。任何 hash 修改必须保留这个测试通过。
