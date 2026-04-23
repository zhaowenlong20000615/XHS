# libtiny x-mini-sig — 算法逆向(50% 完成 + 字节级验证)

**日期**: 2026-04-14 (第二轮更新)
**方法**: Unicorn 黑盒当 oracle + 内存差分追踪 + SHA-256 输入/状态捕获 + byte-mixer 动态字节追踪

---

## 一句话总结

**`x-mini-sig` 用标准 SHA-256,canonical 字符串完全确定,后 16 字节已字节级证明**:

```
sig[16:32] = SHA-256(METHOD + "\n" + PATH + "\n\n" + body_sha256_hex + "\n" + mua_header_b64 + "..")[16:32]
```

剩 `sig[0:16]` 来源未知(已排除 50+ 种候选)。

---

## 证据链

### 1. libtiny 用标准 SHA-256(已证)

通过 hook PC `0x39d7a4`(IV reset point),捕获到 transform 启动时的 state buffer:

```
state[8:40] = 67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b
```

8 个 LE u32 解码:
- `0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a 0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19`

→ **完全等于标准 SHA-256 IV**(`6a09e667bb67ae85...5be0cd19`)。

### 2. 第一次 SHA-256 是 `SHA-256(body)`

捕获到 transform 的 input block(at PC `0x3a04f4`):

```
input = 61626380000000...000000000000000000000000000000000000000000000018
        ^^^^^^                                                          ^^
        "abc"                                                          24 bits
```

这是 SHA-256 padding 标准格式:`"abc"` (3 字节) + `0x80` + 52 个 0 + length=24 bits。

→ **第一次 transform = SHA-256("abc")**(body 的 hash)。

### 3. 第二次 SHA-256 跨 7 个 block,处理 421 字节 canonical 字符串

捕获到 final padded block:

```
content = "zk2ZWEzZDgwZDQyIiwidiI6IjIuOS41NSJ9.."  (37 字节)
length field at end = 0x0d28 = 3368 bits = 421 bytes
```

→ **第二次 hash 输入是 421 字节,7 个 64-byte block(384 满 + 37 末)**。

### 4. canonical 字符串格式确定(byte-exact)

通过 capture 第 1 块、第 2 块、第 7 块的内容拼回:

```python
canonical = f"{METHOD}\n{PATH}\n\n{body_sha256_hex}\n{mua_header_b64}.."
```

具体例子(GET /api/sns/v1/test, body='abc'):

```
GET                                                                # 3 bytes
\n                                                                 # 1 byte
/api/sns/v1/test                                                   # 16 bytes
\n                                                                 # 1 byte
\n                                                                 # 1 byte
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad   # 64 bytes (body sha256 hex)
\n                                                                 # 1 byte
eyJhIjoiRUNGQUFGMDEi...zk2ZWEzZDgwZDQyIiwidiI6IjIuOS41NSJ9         # 332 bytes (mua header b64)
..                                                                 # 2 bytes
```

总长 = 3+1+16+1+1+64+1+332+2 = **421 bytes** ✓

`mua_header_b64` 是 `x-mini-mua` JWT 格式的第一段(在第一个 `.` 之前)。

### 5. 后 16 字节字节级匹配(3/3 测试用例)

```
| METHOD | PATH                       | BODY      | sig[16:32] match |
|--------|----------------------------|-----------|------------------|
| GET    | /api/sns/v1/test           | b"abc"    |       ✓          |
| GET    | /api/sns/v1/feed           | b""       |       ✓          |
| POST   | /api/sns/v2/note/like      | b'{...}'  |       ✓          |
```

→ 16 字节完全匹配的概率 = 2^-128 ≈ 0。**canonical 公式 100% 证实**。

---

## 未解部分:`sig[0:16]` — 已定位到具体 byte-mixing 函数

### 关键发现:不是 hash,是 byte-level XOR mixer

**数据流**(已验证):
1. `0x701e4324` 在 byte-assembly 开始时已经包含 `SHA-256(canonical)` 的完整 32 字节(包括前 16 字节)
2. 函数 PC 范围 `0x160000-0x167000` 把前 16 字节"翻译"成 sig[0:16],后 16 字节不动
3. 16 个独立的 STRB 指令分别写 sig[0..15],每个在不同的 PC(典型 CFG-flatten 散布)

### sig[0] 的具体计算(已反汇编)

`PC 0x163714: strb r0, [r5]` 写入 sig[0]。`r0` 是一长串 EOR 的累积:

```asm
ldrsb  r1, [r6, #0x2b3]        # signed load
ldrb   r2, [r6, #0x2b4]
cmp    r1, #-1
ldrb   r0, [r6, #0x2ae]        # r0 init
ldrb   lr, [r6, #0x29b]
it     le
eorle  r3, r2, #0x1b           # conditional const XOR
strb   r3, [r6, #0x2b5]        # ★ write back to buffer (state evolves!)
eors   r0, r5                  # r5 = [r6+0x2a5]
eor    r0, r0, lr
ldrb   r1, [r6, #0x29c]        # XOR in
eors   r0, r1
ldrb   r2, [r6, #0x2a6]
eors   r0, r2
ldrb   r3, [r6, #0x2b1]
eors   r0, r3
ldrb   r1, [r6, #0x29e]
eors   r0, r1
... (~15 个 LDRB+EORS)
strb   r0, [r5]                # ★ store sig[0]
```

→ 这是一个 **byte-level XOR mixer**,从 `r6 + 0x296..0x2b5`(48 字节 buffer)读 ~15 字节,XOR 累积到 r0,**同时回写 buffer 自身**(`strb r3, [r6+0x2b5]`)使 buffer 成为 evolving state。

### 源 buffer 内容(已抓)

在 PC `0x163714` 触发时(sig[0]=0x47 即将写入),`r6 = 0x701e3ed8`,buffer 内容:

```
r6+0x290: 78 01 78 f0 fb ed c1 99 29 ee c7 29 95 31 62 c4
r6+0x2a0: 93 23 46 01 5d 46 8c 03 06 0c 18 01 03 34 2e 68
r6+0x2b0: d0 bb 6d da b4 af 00 00 ...
```

48 字节 active data + 后续 zero padding。**这个 buffer 跟 SHA-256(canonical) state 没有简单关系**(byte 集合不同,既不是 LE/BE permutation 也不是 XOR mask),它是 byte-mixer 函数自己生成的中间态。

### 难点

byte-mixer 函数有 16 个独立 basic block(每个出一个字节),每个 block:
1. 多次 LDRB 从 r6 buffer 读
2. 多次 EORS 累积到 r0
3. **在同一 buffer 写回**(state evolution)
4. STRB sig[i]

**每个 block 的读/写偏移不同,且都是 CFG-flatten 散布**(`mov pc, rN` 计算跳转)。要纯 Py 复现需要:
1. 还原 16 个 block 的实际执行路径(每个 block 几十条 LDRB+EORS+STRB)
2. 还原 buffer 的初始值(在 byte-mixer 之前由谁/如何生成)
3. 模拟 buffer 的 evolving state

**估计工作量**:每个 block 数小时反汇编 + 反推数据流,16 个 block ≈ 1-3 天专心工作。

### 替代方案(实用)

如果不要求纯 Py 复现,可以混合:
1. **Pure Py**: `sig[16:32] = SHA-256(canonical)[16:32]`
2. **Unicorn 单点 mini-emulation**: 把 byte-mixer 函数(PC 0x160000-0x167000,~28KB)在 Unicorn 里调一次,输入是 r6 buffer 初始状态(也需要单点抓),输出 16 字节 sig[0:16]
3. 总时间:**setup 几 ms + 单次调用几十 ms**

但用户要求纯算法逆向,不要 .so 依赖。所以这是 fallback,不是解。

---

### 关键原理:为什么 byte-mixer 这么难

XHS 用了 **anti-RE byte mixer**,把 16 字节 hash 拆成 16 个独立 basic block,每个 block 读混合 buffer 多个偏移并写回。这种设计的 RE 对抗性:

- **状态依赖**: buffer 会被前一个 block 的 STRB 修改,所以 block 顺序敏感
- **CFG-flatten 隐藏顺序**: 16 个 block 散在不同 PC,通过 `mov pc, rN` 串联,静态看不出执行顺序
- **每个 block 读 ~15 字节**: 单 byte 输出依赖 ~15 个输入字节,brute force 是 256^15 ≈ 2^120
- **常量时间**: 没有数据相关分支,timing attack 无效

这是 SHA-256 之外的**第二层 anti-tampering**: 即使你算出 SHA-256(canonical),还需要正确执行这个 byte mixer 才能产生最终 sig 的前 16 字节。

后 16 字节直接用 SHA-256 输出可能是为了 **server 端可以独立验证**(同样的逻辑反推),前 16 字节作为 anti-replay/anti-RE 的 "armor"。

---

## 当前 Pure-Python 复现

已写到 [`scratch/shield_hunt/breakthrough/libtiny_sig_algo.py`](../scratch/shield_hunt/breakthrough/libtiny_sig_algo.py):

```python
def compute_sig_last16(method: str, url: str, body: bytes,
                       mua_header_b64: str) -> bytes:
    """sig[16:32] — fully reproduced (no Unicorn, no .so file needed)."""
    parsed = urlsplit(url)
    canonical = f"{method}\n{parsed.path}\n\n{hashlib.sha256(body).hexdigest()}\n{mua_header_b64}.."
    return hashlib.sha256(canonical.encode()).digest()[16:32]
```

**测试**: `python3 scratch/shield_hunt/breakthrough/libtiny_sig_algo.py` → 3/3 ALL MATCH。

---

## 与之前文档的关系

- [docs/30_libtiny_analysis.md](30_libtiny_analysis.md) 之前判断 libtiny 静态完全不可逆,**已被推翻** —— 用 Unicorn 当 oracle 做差分内存追踪,可以从黑盒里精确反推算法
- 之前找到 `scratch/native_trace/libtiny_oracle.json` 里 5 个 sig pair 的暴力破解失败,因为没用 mua_header_b64 作为 canonical 的一部分。这次用 Unicorn 可以**实时获取每次 sign 的 mua_header_b64**,因此能精确构造 canonical
- [docs/29_dynamic_hook_spec.md](29_dynamic_hook_spec.md) 提到的 hook 需求**已不再需要外部窗口**:Unicorn 自带的 oracle 完全够用

---

## 下一步计划

1. **解开 sig[0:16] 来源**(优先):
   - 试 AES-128-ECB 假设
   - 用更细粒度的 trace 看 sig[0:16] 在 emulator 内存里的形成过程
   - 找另外一个 SHA-256 的 input(如果存在第三次 SHA-256)
2. **复用方法到 x-mini-s1**:同样的 LibTinySigner oracle + memory tracing,推导其 canonical 格式
3. **复用方法到 shield**(libxyass):同样手法,但需要切到 XhsShieldSigner

每一步都不再依赖外部 dynamic hook —— 只需 Unicorn + 一些 Python 解析时间。

---

## 2026-04-14 第二轮更新:sig[0] 字节级公式已完全验证

### 关键突破

#### 1. 48-byte buffer 实际只有 38 bytes active

之前文档说 r6+0x290..r6+0x2b5 是 48 字节 buffer。**实测在 sig[0] 写入时刻只有 38 字节有效**(r6+0x290..r6+0x2b5),之后的区间全是 0x00。更大的 state(0x2b6..0x3a3)是 byte-mixer 在产生 sig[1..15] 过程中**逐步**写入的。

#### 2. sig[0] 的 XOR 公式完全 reproduce

用 14 个固定 offset 对 38-byte buffer 做 XOR,得到 sig[0]:

```python
INDICES_SIG0 = [30, 21, 11, 12, 22, 33, 14, 15, 25, 35, 16, 37, 6, 8]

def sig0(buf_38: bytes) -> int:
    r = 0
    for i in INDICES_SIG0:
        r ^= buf_38[i]
    return r
```

**字节级验证**(offset 均相对 buf[0] = r6+0x290):

| 输入 | buf[30] | buf[21] | buf[11] | ... | XOR 结果 | 实际 sig[0] |
|------|---------|---------|---------|-----|---------|-------------|
| GET /test, body='abc' | 0x2e | 0x46 | 0x29 | ... | **0x47** | 0x47 ✓ |
| GET /test, body='abd' | 0xa4 | 0x70 | 0x83 | ... | **0x11** | 0x11 ✓ |

#### 3. 16 个 STRB PC 全部定位

```
sig[ 0]=0x163714  sig[ 8]=0x164962
sig[ 1]=0x160012  sig[ 9]=0x1649be
sig[ 2]=0x164174  sig[10]=0x164a2c
sig[ 3]=0x1634e2  sig[11]=0x163bb4
sig[ 4]=0x1639e8  sig[12]=0x161fc6
sig[ 5]=0x164f24  sig[13]=0x160f54
sig[ 6]=0x16193e  sig[14]=0x165c68
sig[ 7]=0x163b26  sig[15]=0x160624
```

#### 4. Buffer 是完全 input-dependent,变化 ≈ 75%

| 输入对 | 38 字节中差异数 |
|--------|----------------|
| body='abc' vs body='abd' | 36/48 |
| path '/test' vs '/feed' | 37/48 |
| GET vs POST + different body | 几乎全变 |

→ buffer 是 canonical 的某种 hash-like 派生,每一 bit 改变都能 cascade 到 38 个字节。

#### 5. Buffer 不是 SHA-256/MD5/SHA-1/RC4/AES

已逐一测试排除(都不匹配 buf[0:32] 或 buf[:16] vs 实际 buf):

- SHA-256(canonical) — 不匹配
- SHA-256(SHA-256(canonical)) — 不匹配
- SHA-256(canonical[0:16]) / [16:32] — 不匹配
- SHA-256(mua_b64) — 不匹配
- MD5(canonical) — 不匹配
- SHA-1(canonical) — 不匹配
- RC4(canonical_sha, 38 bytes) — 0/38 字节匹配
- AES-128(canonical_sha[0:16], key=canonical_sha[16:32]) — 0/16 匹配

#### 6. Byte-mixer 有 CFG-dispatch constant table at 0x57b000

从 trace 看, byte-mixer 执行过程中,**从 libtiny 镜像 0x57b000 页读取 58 次 4-byte 常量**,这些都是基本块跳转地址(值的形式 `0x03XXXXXX`,全部位于 libtiny .text 段 0x000..0x573ce0 内)。这证实了 CFG-flatten: byte-mixer 没有固定的执行路径,而是通过一个 indirect-jump table 串联 16 个输出字节的计算。

静态反汇编这个 dispatch table 是下一步的关键: 如果能 rebuild 16 个 block 的执行顺序和每个 block 的 arithmetic, 就能 offline 重放 byte-mixer。

### 3 处标准 SHA-256 IV — 已证实只有 2 个 instance

libtiny 有 3 个 IV pool locations (`0x47e040`, `0x47ea50`, `0x4889b0`),**全部是标准 SHA-256 IV** —— 这只是因为编译器内联了 sha256_init 的 IV 字面常量 3 次,并不意味着有 3 个独立的 hash instance。

通过在 PC `0x39f752`(last-u32 write)挂 hook 并 dump ctx 状态,我们捕获到 8 次 block-final 事件:

| 块号 | 完整 h[0..7] 输出 | 身份 |
|------|-------------------|------|
| 0 | `ba7816bf...f20015ad` | SHA-256(body="abc") ✓ |
| 1 | `22bcaa3c...2d252a07` | canonical 链式状态,block 1/7 |
| 2 | `876c1e21...5262d309` | canonical block 2/7 |
| 3 | `796aa98f...92eca2fe` | canonical block 3/7 |
| 4 | `18782036...c09fe165` | canonical block 4/7 |
| 5 | `79f3daca...415e5704` | canonical block 5/7 |
| 6 | `b8300c6d...cbe842be` | canonical block 6/7 |
| 7 | `61779c1a...dcfc736a` | SHA-256(canonical) ✓ |

→ 只有 **2 个** hash instance(body + canonical),没有第三个。但 6 个中间链式状态是 **pure-Python reproducible** 的: 把 canonical 切成 64 字节的 block,逐块跑 SHA-256 compression,每次记录 h[0..7]。

### Byte-mixer buf 不是 digest 的字节选择

尝试: 对 buf 中的 38 个字节,在 8 个 digest 的 256 个 byte 位置里搜索匹配 —— **14 个 buf 字节在所有 8 个 digest 中完全不存在**(如 `0xf0`, `0xfb`, `0xc1`, `0x99`, `0xee`, `0xc7`, `0x95`, `0x31`, `0x93`, `0x8c`, `0x2e`, `0xd0`, `0xbb`, `0xaf`)。

→ buf 不是 digest 字节的 permutation / selection。它必须是**字节级的计算结果**(可能是 XOR/ADD/SUB 组合),candidates 包括:
- canonical_sha 的字节之间 XOR/ADD
- 8 个 digest 里字节之间的线性组合
- 一个 byte-mixer 内部 table 的 SBOX + 输入 XOR

这些假设的验证需要**完整反汇编 byte-mixer 的 38 个写入点**(PCs `0x160XXX-0x165XXX`),用 capstone backward-walker 对每个 STRB 追溯前 ~40 条指令的数据流。

### 更新后的 pure-Python reproducer stub

```python
def compute_all_sha256_chain_states(canonical: bytes) -> List[bytes]:
    \"\"\"Run SHA-256 block-by-block, return state after each block.
    Each state is the 32-byte h[0..7] concatenation.
    Ready to use as input to the byte-mixer once its formula is known.\"\"\"
    import struct, hashlib
    # Pad canonical per SHA-256 spec
    msg = canonical + b'\\x80'
    while (len(msg) + 8) % 64 != 0:
        msg += b'\\x00'
    msg += struct.pack('>Q', len(canonical) * 8)
    # Initial IV
    h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    K = [  # SHA-256 round constants
        # ... (64 entries omitted)
    ]
    states = []
    # Process each 64-byte block, record h after each
    # (full implementation would use a custom SHA-256 core)
    # Alternatively: use the python hashlib trick of clone-and-finalize
    return states
```

---

### 2026-04-14 第三轮:byte-mixer 描述符结构体 + 字符串输入

#### 发现 1: byte-mixer 读取 header name 字符串 `"x-mini-mua"` 作为输入

sig[0] 写入之前,byte-mixer 从 heap `0x60008738` 读取 **11 字节**:

```
0x60008738: 78 2d 6d 69 6e 69 2d 6d 75 61 00  = "x-mini-mua\0"
```

对应 PC `0x162368`,循环读取。这是 11 次独立的 LDRB(每字节一次)。读到的字节会被 memcpy 到 r6 stack frame 的某个位置,然后 byte-mixer 对它们做 XOR。

**含义**: sig 的前 16 字节**隐含编码了 header 名字**(`x-mini-mua`),这是一种**字段绑定**(field-binding)防御: 同一套字节不能被当作 `x-mini-sig` 以外的 header 用。这印证了为什么 SHA-256(canonical) 的前半被额外"armor"了。

#### 发现 2: r6 stack frame 藏着一个描述符结构体

在 sig[0] 写入时刻,dump r6+0x100..r6+0x150 得到:

```
r6+0x110: 98 3e 1e 70  c8 46 5c 40  01 00 00 00  00 00 00 00
                       ^^^^^^^^^^^ = 0x405c46c8  (libtiny .bss 指针)
r6+0x120: 38 87 00 60  cc 46 5c 40  cc 46 5c 40  38 87 00 60
          ^^^^^^^^^^^ = 0x60008738  (heap: "x-mini-mua" 字符串指针)
                       ^^^^^^^^^^^ = 0x405c46cc  (libtiny .bss 下一字段)
r6+0x130: 0a 00 00 00  00 00 00 00  00 00 00 01  00 00 00 00
          ^^^^^^^^^^^ = 0x0000000a = 10 (= len("x-mini-mua"))
```

这是一个 **pointer descriptor struct**,byte-mixer 读取它以间接获取输入数据:
- header name 字符串的地址 + 长度
- libtiny .bss 里若干常量字段的地址(可能是 key material)
- sig output buffer 的地址 (另有 r6+0x220..0x28f 一大段指针表,16 个条目分别指向 0x701e4325..0x701e4334 即 sig buffer 的 16 个字节位置)

#### 发现 3: byte-mixer 输入源头(sig[0] 之前)

| 源区域 | 读次数 | 内容 |
|--------|--------|------|
| r6 stack frame | 916 | byte-mixer 的 working buffer,包含 pointer descriptor struct + 中间状态 |
| heap `0x60008738` (x-mini-mua) | 11 | header name 字符串字节 |
| libtiny .bss `0x405c46c8/e8` | 2 | .bss 里 2 个单字节常量(值 `0x00`, `0x01`) |

非 stack 的外部读 **只有 13 个字节** —— 11 个来自 `x-mini-mua` 字符串 + 2 个来自 .bss。这意味着 buf 的 38 字节**几乎全部来自 r6 stack 的预填充数据**,而 stack 的预填充又是更早的 sign() 流程(SHA-256 生成、canonical 构造、mua payload 拆解等)所 memcpy 出来的。

#### 完整的数据流假设

```
canonical_sha --+
                |
x-mini-mua ----+---> [各种 memcpy 到 r6 stack frame 不同 offset]
                |
libtiny .bss --+
                |
                v
        [r6 stack descriptor struct + data buffer]
                |
                v
        [byte-mixer: 16 basic blocks + CFG-flatten dispatcher]
                |
                v
        [sig output buffer 0x701e4324 + 16 字节]
                |
                v
        sig[0:16]  (sig[16:32] 直接来自 sha256(canonical)[16:32])
```

#### 为什么这个 byte-mixer 对防御有效

XHS 的 byte-mixer 不是一个"白盒密码",但它实现了 **sig to header-name binding**:通过把 `"x-mini-mua"` 字节直接 XOR 到 sig 的前 16 字节里,服务器可以:
1. 计算 SHA-256(canonical) 得到后 16 字节(直接对比)
2. 计算前 16 字节时,同样跑一遍 byte-mixer(服务器端逻辑同样嵌入了 header name 字节)

这样即便攻击者算出了 SHA-256(canonical),前 16 字节没有 header name 的正确混入就会失败验证。

### 如何 100% 纯 Py 复现 sig[0:16](明确路径)

1. **对 14 个相关 STRB PC 做静态反汇编**(针对 sig[0] 用到的 14 个 r6 offset),提取 XOR 公式(源寄存器 + 偏移)
2. **追溯 r6 stack frame 的 prefill 代码**:找出谁把 `x-mini-mua` / `.bss 常量` / `canonical_sha` memcpy 到 r6+{特定 offset} 的
3. **把以上两步组合成一个 Python 函数**: `input (canonical_sha, x_mini_mua_name_bytes, bss_const_bytes) -> buf_38 -> XOR formula -> sig[0:16]`

这比"完全反编译 byte-mixer"要简单得多 —— 我们不需要理解 16 个 output 的 CFG dispatch,只需要理解**数据从哪里来**,因为 XOR 公式我们已经能通过 dynamic trace 提取。

---

## 剩余工作(按优先级)

### P0: 反汇编 byte-mixer 的 38 个 STRB 前缀(完成 sig 的最后一公里)

每个 STRB PC 前面有 ~40 条指令的 EORS+LDRB 链。对每个 PC:
1. 用 capstone 静态反汇编从 PC 向后走 40 条(处理 CFG-flatten 的 `mov pc, rN`)
2. 找出所有 LDRB 的源 base(r6+offset 或某个 canonical_sha 指针)
3. 提取 XOR 公式: `buf[out_idx] = XOR(bytes at specific (base, offset) pairs)`

如果 base 不是 r6(而是 canonical_sha 或 8 个 digest 中的某一个),那就**直接搞定了** —— 因为 canonical_sha 和 digest 都是 pure-Py 可复现的。

### P1: 38 个 PC 的 dispatch table 解析

CFG-flatten 用了 `0x57b000` 的 368-byte 常量表来串联 basic block。如果能 rebuild execution order,就能手工重写 byte-mixer 为一个 pure-Py 函数。

### P2: Fallback

如果纯 Py 反汇编太耗时,用 Unicorn 作 sig 计算器(目前 `LibTinySigner.sign()` 已经能工作,每次 ~150ms)。虽然不符合 "no .so dependency" 的终极目标,但作为过渡方案可用。

### 当前 Pure-Python 状态

```python
# WORKS (proven byte-exact):
def compute_sig_last16(method, url, body, mua_header_b64) -> bytes:
    canonical = build_canonical(method, url, body, mua_header_b64)
    return hashlib.sha256(canonical).digest()[16:32]

# STUB (needs byte-mixer and buffer derivation):
def compute_sig_first16(method, url, body, mua_header_b64) -> bytes:
    buf = derive_byte_mixer_input(...)   # <-- UNKNOWN
    return byte_mixer_xor(buf)           # <-- offsets known for sig[0]; sig[1..15] pending
```

### 下一轮卡点

1. **找到 byte-mixer buffer 的 derivation algorithm** (最关键)
   - 候选: 第三个 SHA-256 的 input 还没被定位
   - 方法: 用 MEM_WRITE hook 监控 r6+0x290..r6+0x2b5 区间,找出真正写入这里的 memcpy 源头
   - 具体观察: 38 个 single-byte writes 都来自 byte-mixer 自己的 PC 范围,所以 buffer 是 byte-mixer 内部计算的,不是外部 memcpy 进来的。那么数据来源是哪里? byte-mixer 读取了什么?
2. **提取 sig[1..15] 的 XOR offset lists**
   - 当前 dynamic trace 因 CFG-flatten 而被 noise 淹没
   - 替代: 对每个 STRB PC,静态反汇编前 ~40 条指令的 LDRB+EORS 链 (在 Ghidra 里手动跟,或者写一个 capstone-based backward-walker)

### 用户要求记录

**用户明确要求**: 先把 x-mini-sig 完全逆向完,再动 x-mini-s1、x-mini-mua、shield。目前 sig[16:32] 已完成,sig[0] 有可验证公式但依赖未知 buffer。**sig 这一个字段尚未 100% 纯 Py 可复现** —— 我们有公式但 buffer derivation 是卡点。
