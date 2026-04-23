# 真机 RC4 明文采集需求 v1(给 xhs-capture 窗口)

**目的**: 抓 libxyass 在真机上构造 shield 时,RC4 加密的 **83 字节明文**,
用来对比我们 emulator 里 RC4 明文的差异,定位 shield 最后 4 字节 gap。

**一次性采集**: 明文内容是 install-stable(和签哪个请求无关),跑一次 xhs 冷
启动触发任何一个签名请求就够了。

---

## 0. 背景上下文(让你快速对齐)

这一路追查的结论:

1. xhs shield (100 bytes, base64 进 `shield:` header) 由两段组成:
    - 前 84 字节: **install-stable 的 "device_prefix"**(同一 install 签任何
      URL 都一样)
    - 后 16 字节: **per-request hash tail** (= `data_in XOR DEVICE_MASK_16B`)

2. 前 84 字节里 **80 字节已经在我们 emulator 里 byte-exact 正确**,只有位置
   21-24 (0-indexed) 四个字节不对:
   ```
   real: ... 1e d3 11 b5 21 b0 fd fd ...
   emu:  ... 1e dd de 1f d1 b0 fd fd ...
             ^^ ^^ ^^ ^^
             byte 21-24 错
   ```

3. 追进 libxyass 反编译 + 动态 trace,定位到 shield[2..84] 的产生路径:
   ```
   shield_chars[2..84]  ← base64 of raw_buf[0..100]
   raw_buf[16..98]      ← RC4_encrypt("std::abort();" as key, plaintext_83)
   ```
   - RC4 的 key 是 libxyass .rodata 里硬编码的字符串 **"std::abort();"** (13 字节)
   - 我们 emulator 跑出来的 RC4 key 字节级就是这个,所以 **key 没有差异**
   - shield 差异必然来自 **RC4 明文的差异**

4. 我们反算出真机 RC4 密文 bytes 4-7 应该是 `31 1b 52 2b`(我们 emulator 是
   `dd e1 fd 1b`),这 4 字节通过 4-bit 位移映射到 shield 字节 21-24。

5. **问题**: 我们 emulator 里 RC4 明文 bytes 4-7 = `00 00 00 01`(看起来是 u32
   常量 "1")。按同 key → 同 keystream 反推,真机明文 bytes 4-7 应该是 `ec fa
   af ??` —— 完全不同的字节模式。不是一个 u32 常量,而是看起来像 hash / 随机
   数据。

6. **我需要的是**: 真机上 RC4 明文的完整 83 字节。我对比两边明文找出第一个
   diff 字节,然后回溯那个字节的来源(是哪个 bss global、还是某次 hash 的输
   出、还是从 keychain 读的),最终在 emulator 里 patch 成正确值。

---

## 1. Hook 目标 = libxyass 里 RC4 encrypt 第一次 store 的位置

### 符号 / 偏移

- 模块: `libxyass.so` (32-bit ARM / Thumb-2)
- Hook 偏移: **`libxyass_base + 0x28a04`**
- 指令: `strb r1, [sl], #8`  —— post-increment store,1 字节
- 这是 RC4 内层循环第一个 output byte 的 store 指令

这个偏移对我们抓过的 libxyass.so(xhs 9.19.0, build 9190807)是稳定的。如果你
的设备是同一版本应该直接能用。如果 APK 版本不同,你得自己找一下 `strb r1,
[sl], #8` 的模式,或者更鲁棒一点走"RC4 KSA 结尾 + 进循环第一次迭代"。

### 上下文(可以跳)

这段反编译出来是经典 RC4 内循环:
```
+0x28a00: eor.w    r1, r1, r2        ; r1 = keystream_byte XOR plaintext_byte
+0x28a04: strb     r1, [sl], #8       ; *sl = r1 (ciphertext byte 0); sl += 8
+0x28a08: add.w    r1, r3, #2         ; i = (r3 + 2) & 0xff
...
+0x28a2e: ldrb     r2, [fp, #-0x7]   ; plaintext_byte (for byte 1)
+0x28a32: eor.w    r1, r1, r2
+0x28a36: strb     r1, [sl, #-0x7]   ; ciphertext byte 1
... (repeat 6 more times, 8 bytes per iteration)
+0x28a4a: blt      #0x28e06           ; loop
```

`sl` = r10 = output buffer(密文),`fp` = r11 = plaintext buffer,`ip` = r12 =
RC4 key base(= libxyass 里 "std::abort();" 的 rodata 地址),`r0` = S-box base。

---

## 2. Hook 只要在**第一次命中**时 dump 一次就够

加个 `this._captured` flag,第二次进来就 return,不要每轮都 dump,否则日志爆炸。

### 要 dump 的东西

在第一次命中 `+0x28a04` 时,dump 以下全部:

| 字段 | 来源 | 用处 |
|---|---|---|
| `regs` | `r0..r12, sp, lr, pc` | 所有寄存器状态 |
| `plaintext_region_hex` | `r11 - 16 .. r11 + 112` (128 bytes) | **核心** — RC4 明文 |
| `ciphertext_region_hex` | `r10 - 8 .. r10 + 120` (128 bytes) | RC4 密文 (验证) |
| `sbox_hex` | `r0 .. r0 + 1024` (1024 bytes = 256 × u32) | RC4 S-box |
| `rc4_key_hex` | `r12 .. r12 + 32` (32 bytes) | 验证 key = "std::abort();" |

**为什么读 `r11 - 16 .. r11 + 112`**: 反编译显示 RC4 读 plaintext 用
`[fp, #-7]` 到 `[fp, #-1]` 的负偏移,说明 fp 可能是 plaintext 的某个中间位置
(比如 plaintext + 7),我们 dump 前后一大段保险起见。

**为什么读 `r10 - 8`**: `+0x28a04` 是 **post-increment** store,hook 命中时 r10
已经被 +8 了,所以密文起点是 `r10 - 8`。

---

## 3. Frida 脚本(直接可跑)

```javascript
// hook_rc4.js
const LIBXYASS = Module.findBaseAddress("libxyass.so");
if (!LIBXYASS) {
    console.error("libxyass.so not loaded");
} else {
    console.log(`libxyass @ ${LIBXYASS}`);
}

const RC4_LOOP_OFFSET = 0x28a04;  // strb r1, [sl], #8
const HOOK_ADDR = LIBXYASS.add(RC4_LOOP_OFFSET);

// Thumb bit: +1 because it's Thumb code
Interceptor.attach(HOOK_ADDR.or(1), {
    onEnter(args) {
        if (this._captured) return;
        this._captured = true;

        const ctx = this.context;

        const toHex = (bytes) => {
            const arr = new Uint8Array(bytes);
            let s = "";
            for (let i = 0; i < arr.length; i++) {
                s += arr[i].toString(16).padStart(2, "0");
            }
            return s;
        };

        const safeRead = (addr, size) => {
            try {
                return toHex(ptr(addr).readByteArray(size));
            } catch (e) {
                return `READ_ERR: ${e.message}`;
            }
        };

        const out = {
            format_version: 1,
            tag: "rc4_capture",
            captured_ms: Date.now(),
            libxyass_base: LIBXYASS.toString(),
            hook_offset: "0x" + RC4_LOOP_OFFSET.toString(16),
            regs: {
                r0:  ctx.r0.toString(),
                r1:  ctx.r1.toString(),
                r2:  ctx.r2.toString(),
                r3:  ctx.r3.toString(),
                r4:  ctx.r4.toString(),
                r5:  ctx.r5.toString(),
                r6:  ctx.r6.toString(),
                r7:  ctx.r7.toString(),
                r8:  ctx.r8.toString(),
                r9:  ctx.r9.toString(),
                r10: ctx.r10.toString(),  // sl: ciphertext output (post-incremented!)
                r11: ctx.r11.toString(),  // fp: plaintext input region
                r12: ctx.r12.toString(),  // ip: RC4 key base
                sp:  ctx.sp.toString(),
                lr:  ctx.lr.toString(),
                pc:  ctx.pc.toString(),
            },
        };

        // Plaintext: read fp - 16 .. fp + 112 = 128 bytes
        const fp = ctx.r11;
        out.plaintext_base    = fp.sub(16).toString();
        out.plaintext_hex     = safeRead(fp.sub(16), 128);

        // Ciphertext: read (sl - 8) .. (sl - 8 + 128) = 128 bytes
        // sl was already post-incremented by 8 when we hooked, so sl - 8 is
        // the real start of the output buffer.
        const sl = ctx.r10;
        out.ciphertext_base   = sl.sub(8).toString();
        out.ciphertext_hex    = safeRead(sl.sub(8), 128);

        // S-box: 256 × u32 = 1024 bytes
        out.sbox_base         = ctx.r0.toString();
        out.sbox_hex          = safeRead(ctx.r0, 1024);

        // RC4 key: 13 bytes "std::abort();", but dump 32 for safety
        out.rc4_key_base      = ctx.r12.toString();
        out.rc4_key_hex       = safeRead(ctx.r12, 32);

        send({ tag: "rc4_capture" }, JSON.stringify(out));
        console.log("[rc4_hook] captured — detaching");
    }
});

console.log(`[rc4_hook] installed at ${HOOK_ADDR}`);
```

### Python 端接收 message,落盘

```python
# run_hook.py
import frida, sys, json, datetime, os

OUT_DIR = "scratch/native_trace"
os.makedirs(OUT_DIR, exist_ok=True)

def on_message(message, data):
    if message.get("type") != "send":
        print(message); return
    payload = message["payload"]
    if isinstance(payload, dict) and payload.get("tag") == "rc4_capture":
        # Frida's send() auto-encodes dict payloads; the JSON string is
        # in message['payload'] directly.
        pass
    # The script sends JSON string as second arg
    body = message["payload"]
    # Actually Frida sends send(msg, data) differently — simplify:
    try:
        obj = json.loads(body) if isinstance(body, str) else body
    except Exception:
        obj = body

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(OUT_DIR, f"rc4_capture_{ts}.json")
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
    print(f"wrote {path}")


def main():
    pkg = "com.xingin.xhs"
    device = frida.get_usb_device(timeout=5)
    pid = device.spawn([pkg])
    session = device.attach(pid)
    with open("hook_rc4.js") as f:
        script_src = f.read()
    script = session.create_script(script_src)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    print("spawned, waiting for rc4_capture...")
    sys.stdin.read()


if __name__ == "__main__":
    main()
```

**注意** `send(obj, data)` 在 Frida 里第二个参数是 raw bytes data,我们没用到,
可以省略。上面的 js 里我用了 `send({tag: ...}, jsonStr)` 把 json string 作为
第二个参数,如果 Frida 版本不接受,改成:

```javascript
send({ tag: "rc4_capture", payload: out });
```

然后 Python 端:
```python
obj = message["payload"]["payload"]
```

具体看你之前 xhs-capture 的 send/message 模式,保持一致即可。

---

## 4. 触发 hook

Hook 只在 intercept 跑到 RC4 那一步才命中。随便签一个 xhs 请求即可:

1. `adb shell am force-stop com.xingin.xhs`
2. 启动 Frida spawn
3. 冷启动 xhs,让它自然发第一个网络请求(比如 homefeed / cold_start_config /
   anything — 只要过 `XhsHttpInterceptor.intercept` 就行)
4. 等到 Python 端打印 `wrote scratch/native_trace/rc4_capture_<ts>.json`
5. Ctrl+C 退出 Frida

---

## 5. 产出文件

```
scratch/native_trace/rc4_capture_<timestamp>.json
```

格式就是上面 js `out` 对象序列化的 JSON。大小大约 3-5 KB(4 个 hex 字段,
最大的 sbox 是 2048 hex chars)。

---

## 6. 验收清单

| 项 | 期望 | 说明 |
|---|---|---|
| `regs.pc` | 十进制或 hex 数 | 应该 ≈ `libxyass_base + 0x28a04 + 1` (Thumb) |
| `regs.r12` | 有值 | RC4 key base |
| `rc4_key_hex[0..13]` | `7374643a3a61626f727428293b` | ASCII "std::abort();" —— **必须匹配**,这是我验证你 hook 对了的关键 |
| `plaintext_hex` | 256 hex chars (128 B) | RC4 明文区 |
| `ciphertext_hex[0..16]` | 以 `35` `16` `11` `ed` 开头 | 前 4 字节和我们 emulator 一样,因为 shield 前 20 字节我们对得上 |
| `ciphertext_hex[8..16]` | 不是 `ddde1fd1...` | 应该是 `311b522b...` 附近 —— 这就是我要的证据 |

**只要 `rc4_key_hex` 前 13 字节解出来是 `std::abort();`,就说明 hook 抓对位
置了**,其它字段都可用。

---

## 7. 风险 / 已知问题

- **Hook 位置正确但命中不了**: 可能的原因
  - app 没有进入 `intercept`(没触发任何签名请求)→ 多等会儿 / 刷新一下
    homefeed
  - 你的 libxyass 和我们分析的版本不一样 → 把 `+0x28a04` 附近 32 字节的
    指令对比一下(`frida-trace -i` 或者 `objdump -d libxyass.so | grep -A 40 28a00`)
  - 该 Thumb-bit 错了(我脚本里用 `.or(1)`;shadowhook 就不用)

- **dump 的是 per-request 数据吗?** 不是。明文结构是 install-stable,所以采一
  次就够。你抓的那一次就是一次性样本。

- **多次 sign() 的 plaintext 会变吗?** 不会(这就是 shield device_prefix 的本
  质)。所以 `this._captured` flag 只抓第一次是安全的。

---

## 8. 我拿到之后做什么

1. 对比我 emulator 里的 plaintext 和真机 plaintext,第一个 diff byte 开始往下
   看
2. 那几个 diff 字节来自某个值 —— 要么是 bss 里某个槽、要么是某个函数的返回
   值(比如一次哈希)
3. 我会在 emulator 里 patch 那个源头(最多 1-2 行 Python)
4. 重跑 shield 应该就 84/84 了
5. 然后跑 `note/user/posted` 应该能拿到真实笔记数据(200 OK + body)

---

## 9. 给你省事的 "one-liner" 验证

拿到 json 后我会先跑这一句:

```python
import json
d = json.load(open("scratch/native_trace/rc4_capture_<ts>.json"))
print("key[0..13]:", bytes.fromhex(d["rc4_key_hex"][:26]))
# expected: b'std::abort();'

print("ct[0..8]:  ", d["ciphertext_hex"][:16])
# expected start: '35161100ed...' (first 4 bytes match emulator)
# expected next 4 bytes (shield diff): should NOT be 'ddde1fd1'
```

如果 key 不是 "std::abort();",或 ciphertext 前 4 字节不是 `3516 11ed`,hook 可
能抓的不是我们要的那次 RC4 —— libxyass 里可能有多处 RC4,加个 `r12` 内容验证
一下就行。

---

**文档结束,Frida 脚本就在第 3 节,直接复制跑就行。**
