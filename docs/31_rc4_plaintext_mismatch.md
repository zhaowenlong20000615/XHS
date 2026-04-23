# shield 4 字节 gap 定位到 libxyass 内部 RC4 明文错误

## 追查结果

从反汇编 + 动态 trace 已经定位到 shield 的前 84 字节是如何构造的:

```
shield (100 bytes)
├─ 字节 0..83 (= 前 84 字节 "device_prefix"): base64(100 字节 raw_buf)
│   └─ raw_buf[16..98] = RC4_encrypt(std::abort();, plaintext_83_bytes)
│       └─ plaintext 是一个结构化的 std::string (83 字节)
└─ 字节 84..99 (= 后 16 字节 "tail"): data_in XOR DEVICE_MASK
```

**RC4 key = 固定字符串 "std::abort();"**(13 字节, libxyass 里硬编码的常量)

所以 RC4 key 在我们 emulator 和真机上是完全一样的。出错的一定是**明文**。

## 对齐关系(供后续 debug 参考)

shield 和 raw_buf 之间有 4 bit shift(因为 shield = "XY" + base64(raw_buf)):
```
shield[N] = (raw_buf[N-2] & 0xf) << 4 | (raw_buf[N-1] >> 4)   对 N >= 2
```

已知真机 shield bytes 21-24 = `d3 11 b5 21`,我们 emulator = `dd de 1f d1`。
反推出 raw_buf[19..23]:
```
          byte 19    byte 20    byte 21    byte 22    byte 23
真机 raw:   ed(*)    31          1b          52          2b(*)
我们 raw:   ed       dd          e1          fd          1b
```
(`*` = 只有某一个 nibble 参与计算,另一个 nibble 可能和我们一致)

raw_buf 的第二段是 memcpy 自 `0x60005008`(我们 emulator 里),所以
`buf_05008[4..7]` 对应 raw_buf[20..23],需要从 `dd e1 fd 1b` 变成 `31 1b 52 2b`。

## 明文/密钥流计算

我们捕获到 RC4 写出 8 字节的密文 `35 16 11 ed dd e1 fd 1b`,同时每次写都捕到
`r2` 寄存器 = 即将被 XOR 的明文字节。

| offset | ct (我们) | pt (我们, r2) | keystream |
|---|---|---|---|
| 0 | 35 | 00 | 35 |
| 1 | 16 | 00 | 16 |
| 2 | 11 | 00 | 11 |
| 3 | ed | 01 | ec |
| 4 | dd | 00 | dd |
| 5 | e1 | 00 | e1 |
| 6 | fd | 00 | fd |
| 7 | 1b | 01 | 1a |

由于 key 相同、keystream 相同,真机上**明文必然不同**:
```
真机 pt[4] = keystream[4] XOR 真机 ct[4] = 0xdd XOR 0x31 = 0xec
真机 pt[5] = 0xe1 XOR 0x1b = 0xfa
真机 pt[6] = 0xfd XOR 0x52 = 0xaf
真机 pt[7] = 0x1a XOR 0x2? ≈ 0x3? (高 nibble 要求是 2,但低 nibble 自由)
```

**所以真机 plaintext[4..6] = `ec fa af ??`**,而我们 emulator 里是 `00 00 00 01`。

## 我们 emulator 里的明文结构

明文 83 字节,在 emulator 里位于一段构造在栈上的 std::string,基址
`fp = 0x60004f70`。内容:

```
fp-8..fp-1  (8 B): 00 00 00 01 00 00 00 01     ← u32 (1, 1)  ★ bytes 4-7 在这里
fp..fp+7    (8 B): 00 00 00 02 00 00 00 07     ← u32 (2, 7)
fp+8..+15   (8 B): 00 00 00 24 00 00 00 10     ← u32 (0x24=36, 0x10=16)(长度字段)
fp+16..+22  (7 B): "9190807"                    ← key1 (from libxyass bss)
fp+23..+58 (36 B): "aa293284-0e77-319d-9710-5b6b0a03bd9c"  ← key2 = deviceId
fp+59..+74 (16 B): 6e 84 4c 46 dd f5 6d 42 8a 28 ad 38 c0 10 b1 7f  ← 未知 16 字节
```

关键观察:
1. **RC4 明文 bytes 0..7 对应 fp-8..fp-1(我们这边) = `00 00 00 01 00 00 00 01`**
2. 这看起来是两个 big-endian u32 = 1, 1。这是"固定常量"性质的东西。
3. 真机上同样位置应该是 `?? ?? ?? ?? ec fa af ??`(这 4 字节差不是 u32 值"1",而是看起来像 hash 尾巴)。

## 关键问题

真机上 fp-8..fp-1 的这 8 字节到底是啥?

三种可能:
1. **结构体布局不一样**:真机的 std::string 前面紧挨着的某个栈变量,我们 emulator 把这块初始化成了 u32(1),真机是别的类型(比如一个 16 字节 hash 的尾巴)。
2. **明文起点不一样**:我们 emulator 里 fp 指向的位置,和真机不同。RC4 读的前 8 字节在真机上可能来自 fp-16..fp-9 而非 fp-8..fp-1。
3. **RC4 读的是另一个缓冲**:fp 只是 RC4 整个明文块的某个中段指针,明文实际在另一个地址。

## 给 xhs-capture 窗口的请求

**需要捕获:真机上 RC4 明文的完整 83 字节。**

### Hook 位置

libxyass 里 RC4 加密的入口在 `+0x289xx..+0x28bxx` 区域。RC4 核心循环 from
`+0x28a00` 开始(一次处理 8 字节密文)。

最简单的 hook 点:**`+0x28a04`(第一次 `strb r1, [sl], #8`)**。

此时:
- `sl = 密文输出缓冲` (= 第一次调用时的 dst, 我们 emulator 里是 0x60005008)
- `fp = 明文的某个基址指针` (我们 emulator 里是 0x60004f70)
- `r0 = RC4 S-box 基址`(我们 emulator 里是 0x??)
- `ip = RC4 key 基址`(应该指向 libxyass rodata 里的 "std::abort();")

### 需要 dump 的东西

在 `+0x28a04` 第一次命中时,dump:

1. **寄存器状态**:`r0..r12, sp, fp, lr, pc`
2. **明文区域**:`fp - 16` 开始的 128 字节(覆盖 fp-16..fp+111,保证能抓到完
   整 83 字节明文无论起点在哪)
3. **密文缓冲起点**:`sl - 8` 开始的 128 字节(hook 时 sl 已经被 post-inc
   了,所以 sl-8 是真正的 dst 起点)
4. **S-box**:`r0` 指向的 1024 字节(256 × 4 字节,应该和我们完全一样)
5. **RC4 key**:`ip`(r12)指向的 13-32 字节(验证是 "std::abort();")

### Frida 脚本骨架

```javascript
const RC4_LOOP_OFF = 0x28a04;

const LIBXYASS = Module.findBaseAddress("libxyass.so");
Interceptor.attach(LIBXYASS.add(RC4_LOOP_OFF), {
    onEnter(args) {
        if (this._captured) return;
        this._captured = true;

        const ctx = this.context;
        const out = {
            pc: ctx.pc.toString(),
            r0: ctx.r0.toString(),  // S-box base
            r1: ctx.r1.toString(),
            r2: ctx.r2.toString(),
            r3: ctx.r3.toString(),
            r4: ctx.r4.toString(),
            r5: ctx.r5.toString(),
            r6: ctx.r6.toString(),
            r7: ctx.r7.toString(),
            r8: ctx.r8.toString(),
            r9: ctx.r9.toString(),
            r10: ctx.r10.toString(),  // sl: output pointer (post-incremented)
            r11: ctx.r11.toString(),  // fp: plaintext pointer
            r12: ctx.r12.toString(),  // ip: RC4 key pointer
            sp: ctx.sp.toString(),
            lr: ctx.lr.toString(),
        };

        try {
            // Plaintext region: fp - 16 .. fp + 112 (128 bytes)
            const fp = ptr(ctx.r11);
            out.plaintext_region_base = fp.sub(16).toString();
            out.plaintext_region_hex = fp.sub(16).readByteArray(128);
        } catch (e) { out.plaintext_err = e.toString(); }

        try {
            // Output ciphertext buffer: sl - 8 .. sl + 120
            const sl = ptr(ctx.r10);
            out.ct_region_base = sl.sub(8).toString();
            out.ct_region_hex = sl.sub(8).readByteArray(128);
        } catch (e) { out.ct_err = e.toString(); }

        try {
            out.sbox_base = ctx.r0.toString();
            out.sbox_hex = ptr(ctx.r0).readByteArray(1024);
        } catch (e) { out.sbox_err = e.toString(); }

        try {
            out.rc4_key_base = ctx.r12.toString();
            out.rc4_key_hex = ptr(ctx.r12).readByteArray(32);
        } catch (e) { out.key_err = e.toString(); }

        send({tag: "rc4_capture"}, JSON.stringify(out));
    }
});
```

### 产出文件

```
scratch/native_trace/rc4_capture_<timestamp>.json
```

JSON 格式,每个 hex 字段把 ByteArray 转成 hex 字符串。

### 验收

- [ ] `plaintext_region_hex` 有 128 字节十六进制内容
- [ ] `rc4_key_hex` 前 13 字节解码后 ASCII 是 "std::abort();"(我已知是这个,
      拿来验证 hook 抓对了)
- [ ] `ct_region_hex` 前 8 字节 ≈ 我们 emulator 里的 `35 16 11 ed ?? ?? ?? ??`
     (前 4 字节应该是 35 16 11 ed,和我们一样;后 4 字节应该就是真机的
     正确值 `31 1b 52 2b` 附近,和我们的 `dd e1 fd 1b` 不一样)

## 我这边拿到后的处理

1. 对比真机 plaintext 和我们 emulator plaintext,找出第一个偏差位置
2. 那 8 字节(0 偏差到 8 差异)来自某个在真机上初始化、我们没初始化好的值
3. 如果在 fp-16..fp-1 范围:可能是前一个栈变量的尾巴,需要找出它怎么初始化的
4. 如果在 fp+?:可能是某个 hash 的输出,要定位那个 hash 的调用
5. 一旦确定来源,用一个小的 emulator fix(或者一次性注入值)就能解决

这一步之后 shield 80/84 → 84/84,笔记查询 API 应该就能正常 200 了。

## 背景提醒

- RC4 key = `std::abort();`(13 字节, libxyass rodata 里的常量字符串)
- 明文长度 = 83 字节(对应 shield 位置 0..83,但经过 4-bit shift 所以 shield
  的 2..85 位)
- 密文输出到一个 83 字节的临时 buffer,之后被 memcpy 到 raw_buf(100 字节),
  再 memcpy 到 std::string,最终 base64 编码进入 shield header
- RC4 的 S-box 初始化在 `+0x28906` 附近的 KSA 循环,读 key bytes from `ip`
