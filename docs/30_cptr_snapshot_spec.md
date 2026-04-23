# cPtr Snapshot 采集需求(给 xhs-capture / Frida 窗口)

**目的**: 给 Unicorn 黑盒模拟器提供一份"真机 `libxyass.initialize()` 跑完之后的
完整 C++ 对象图快照",让 emulator 跳过 `initialize()` 的静态初始化链,直接加载
这份快照后跑 `intercept()`,最终产出字节级正确的 `shield` 头。

**背景 / 问题**:
- Unicorn 里 `initialize()` 能跑,但只填了 `cPtr` 前两个 std::string 槽("main"、
  "main_hmac")
- 后续的 `cPtr+0x18..+0x44` 多个 slot 为空,原因是有一条 **C++ once-flag**
  (在 `libxyass +0x26048` 处 `ldrb r0, [r0, r6]` 读 `.bss` 一个字节,标志是否已
  初始化)在我们环境里一直是 0,gate 住了 populate 路径
- 强制绕过 gate 会继续在更深处崩溃 —— `initialize()` 实际依赖**一整张被懒初始
  化的对象图**,多处全局指针、.bss 槽、堆对象相互引用
- 真机一次 dump 整张图 → emulator 加载 → 黑盒跑 `intercept()` 就能通

---

## 1. 采集点

**Hook 函数**: `libxyass.so` 中 native 方法 `initialize(String)` 的**返回时**

- symbol 名: `Java_com_xingin_shield_http_XhsHttpInterceptor_initialize`
- 或相对地址: `libxyass.so + 0x25f68`(Thumb,实际 `+0x25f69`)
- 真机签名: `(JNIEnv*, jclass, jstring) → jlong`
- 返回值 `r0` 就是 `cPtr` 指针(一个堆地址,指向 libxyass 内部分配的 C++ 对象)

**采集时机**: 必须在 `initialize()` **刚返回的那一刻**。此时 `cPtr` 指向的对象图
已经被 libxyass 初始化完整,还没被 `intercept()` 修改。

**采集触发条件**: 冷启动,且是这个 install 第一次调用 `initialize()` 的时候最
干净。如果 xhs 一次启动里多次调用 `initialize()`,只采第一次即可。

---

## 2. 要 dump 的内容

分四块:

### 2.1 `cPtr` 主结构(固定 512 字节)

```
start = cPtr
len   = 0x200    # 保守起见,多抓一点;实际结构 < 0x80 应该够
```

直接 `memcpy(cPtr, 512)`,原样写进文件。

### 2.2 所有从 `cPtr` 里指向的 std::string 堆数据

libxyass 用的是 **libc++ std::string**,12 字节布局,两种模式:

```
offset  LONG 模式(low bit of byte 0 == 1)         SHORT 模式(low bit == 0)
+0x00   u32 cap    (low bit = 1 = long marker)     u8 size*2
+0x04   u32 size                                    10 bytes of inline data
+0x08   u32 data_ptr → heap                         (null terminator at +0x0b)
```

**SHORT 模式不用额外抓**,数据就在 12 字节里。

**LONG 模式**:顺着 `data_ptr` 去堆上读 `cap` 字节(或者 `size + 1`,取大的那个),
把这段堆内存也存进快照。

**递归处理**:扫完 `cPtr[0..0x80]` 这 128 字节里每一对可能的 12 字节 std::string
槽(按 12 字节对齐枚举就行),把每个 LONG 模式的 `data_ptr → bytes` 抓下来。

**注意**:目前已知 `cPtr+0x00` 和 `cPtr+0x0c` 是 SHORT ("main" 和 "main_hmac"),
后面 `+0x18..+0x44` 才是真机上有效数据的位置,**重点抓这些**。

### 2.3 已知可能被引用的额外全局槽

除了 `cPtr` 指向的堆对象,libxyass 还有几处 `.bss` 内的常量 / std::string,
我们已经在 bss_dump 里看到过,比如:

```
libxyass +0x7df10   key2  (LONG std::string, 就是 deviceId UUID)
libxyass +0x7df20   key1  (SSO std::string, 就是 "9190807")
```

这些地址相对 libxyass 的基址。**请顺带 dump 整段 `libxyass_base + 0x7df00 .. 
+0x7e000`**(256 字节),我们在 emulator 里验证这些 bss 槽是否和真机一致。
如果一致就能跳过采集;如果不一致,说明我们的 bss init 也有问题,需要把这段
也塞进快照。

### 2.4 元数据(JSON header)

在 `.bin` 文件前面加一个 **短 JSON header** 描述元数据,方便我们反序列化:

```json
{
  "format_version": 1,
  "captured_at": "2026-04-14T14:35:00+08:00",
  "libxyass_base": "0x76240000",
  "libxyass_sha256": "...",
  "device_id_uuid": "aa293284-0e77-319d-9710-5b6b0a03bd9c",
  "app_build": 85683130,
  "xhs_version": "9.19.0",
  "initialize_token": "main",
  "cptr_addr": "0x7aa4b8c0",
  "cptr_size": 512,
  "strings": [
    {"slot_off": "0x18", "mode": "LONG", "cap": 48, "size": 36,
     "data_ptr": "0x7aa4d8d0", "data_hex": "61613239..."},
    {"slot_off": "0x24", "mode": "SHORT", "size": 9, "inline_hex": "..."}
  ],
  "bss_snapshot": {
    "range": ["0x76317d00", "0x76317e00"],
    "hex": "..."
  }
}
```

---

## 3. 文件格式

两个文件:

```
scratch/native_trace/cptr_snapshot_<timestamp>.json   # 上面那个元数据
scratch/native_trace/cptr_snapshot_<timestamp>.bin    # 纯二进制 cPtr 主段
```

或者把 .bin 的内容 base64 进 JSON,一个文件就行。看你方便。**我这边解析都能
处理**,JSON 里给一个 `"cptr_hex": "..."` 字段就行。

---

## 4. 建议的 Frida 脚本骨架

```javascript
// xhs-capture / frida / scripts / dump_cptr.js
const LIBXYASS = Module.findBaseAddress("libxyass.so");
const INITIALIZE_OFF = 0x25f68;  // Thumb + 0 (函数入口)

const dumpCptr = function (cPtrAddr) {
    const BASE = LIBXYASS;
    const out = {
        format_version: 1,
        captured_at: new Date().toISOString(),
        libxyass_base: BASE.toString(),
        device_id_uuid: "<填>",
        cptr_addr: cPtrAddr.toString(),
        cptr_size: 0x200,
        cptr_hex: ptr(cPtrAddr).readByteArray(0x200)
                  /* 转 hex 字符串 */,
        strings: [],
        bss_snapshot: {
            range: [BASE.add(0x7df00).toString(), BASE.add(0x7e000).toString()],
            hex: BASE.add(0x7df00).readByteArray(0x100) /* 转 hex */
        }
    };

    // 扫 cPtr[0..0x80] 每 12 字节一个槽,解 LONG / SHORT,抓 LONG 的 data_ptr
    for (let off = 0; off < 0x80; off += 12) {
        const slot = cPtrAddr.add(off);
        const b0 = slot.readU8();
        if ((b0 & 1) === 0) {
            // SHORT
            const sz = b0 >> 1;
            if (sz === 0) continue;
            out.strings.push({
                slot_off: off.toString(16),
                mode: "SHORT",
                size: sz,
                inline_hex: slot.add(1).readByteArray(10) /* hex */
            });
        } else {
            // LONG
            const cap = slot.readU32();
            const sz = slot.add(4).readU32();
            const dp = slot.add(8).readPointer();
            if (sz === 0 || sz > 0x10000) continue;  // sanity
            out.strings.push({
                slot_off: off.toString(16),
                mode: "LONG",
                cap: cap & ~1,
                size: sz,
                data_ptr: dp.toString(),
                data_hex: dp.readByteArray(sz + 1) /* hex */
            });
        }
    }

    // 落盘
    send({ tag: "cptr_snapshot" }, JSON.stringify(out));
};

// Hook initialize() 返回
Interceptor.attach(LIBXYASS.add(INITIALIZE_OFF), {
    onLeave: function (retval) {
        // retval 就是 cPtr (作为 jlong,低 32 位有效)
        const cPtrLow = retval.toInt32() >>> 0;
        dumpCptr(ptr(cPtrLow));
    }
});
```

Python 端接到 `cptr_snapshot` tag 的消息,写进
`scratch/native_trace/cptr_snapshot_<ts>.json`。

---

## 5. 采集流程

1. 冷启动前先 kill xhs:`adb shell am force-stop com.xingin.xhs`
2. 启动 Frida spawn:`frida -U -f com.xingin.xhs -l dump_cptr.js --no-pause`
3. app 自动跑到 `initialize()`,hook 触发,dump 落盘
4. 确认 `.json` 文件已生成,stop Frida
5. 把文件放到 `scratch/native_trace/cptr_snapshot_<timestamp>.json`
6. 告诉我文件名,我这边写 loader

---

## 6. 验收标准

快照文件里至少要包含:

- [ ] `cptr_hex`(512 字节)
- [ ] `strings` 列表,至少 `+0x18`、`+0x24`、`+0x30`、`+0x3c` 这四个槽非空
      (这正是我们 emulator 里空的那几个,真机上必然有值)
- [ ] `bss_snapshot.hex`(256 字节,范围 `+0x7df00..+0x7e000`)
- [ ] `libxyass_base` 和 `device_id_uuid` 填对

只要这几项齐了,我就能在 Unicorn 里:
1. 跳过 `initialize()` 调用
2. 把 `cptr_hex` 写到 BumpAllocator 的一块区域,把 `cPtr_lo` 指向它
3. 把 `strings` 里每个 LONG std::string 的 `data_hex` 写到 BumpAllocator,并把
   对应槽里的 `data_ptr` rewrite 成新的 BumpAllocator 地址
4. 把 `bss_snapshot.hex` 写到 libxyass base + 0x7df00
5. 跑 `intercept()` → 应该能自然走完 canon_hi/canon_lo、alt_hash_update、
   op_update、hmac_b64,产出正确的 shield

---

## 7. 非目标(不用抓的东西)

- 不用抓 op_update / hmac_b64 的内部 ctx state(那些是 per-request 的,
  emulator 每次 sign 会自己初始化)
- 不用抓 canonicalize 的原始字节(per-request)
- 不用 dump libxyass 全段 .bss(太大,我们只要 +0x7df00 那一小段)
- 不用反算法(整张图原样搬就行)

---

## 8. 风险 & 备注

- 如果这份快照加载进 emulator 后 `intercept()` 仍然崩 / 产出仍不对 —— 说明
  除了 cPtr 主结构,libxyass 还有其他 .bss / TLS / 线程局部状态需要抓。那时
  我再写一个"第二轮扩展快照"的需求给你。
- 快照绑定 **install + APK 版本**。APK 升级或应用数据被清除后需要重抓一次。
  这和我们现在 DEVICE_MASK 一样是一次性绑定,不是持续采集。
- JSON 文件会比较大(可能几 MB,因为 bss_snapshot 和可能的大 std::string)。
  base64 压缩下会小一些,但不必要 —— Python 读 hex 很快。

---

**我这边的下一步**: 等你产出 `cptr_snapshot_<timestamp>.json`,我写 loader
和端到端测试。
