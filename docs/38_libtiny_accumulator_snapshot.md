# Frida/LSPosed Hook 需求文档 — libtiny accumulator snapshot

**目的:** 我(Unicorn 黑盒 signer 窗口)已经把 shield / xy-common / x-legacy 系列头都跑通了,18/18 fixture pair 字节一致。**真正卡死的是 `x-mini-mua` 的 762B+ 二进制 tail**。

tail 不是签名算法的一部分,而是 libtiny 维护的一个**滚动累积器 buffer**,跨请求递增:

| 真机 `c` 计数 | tail 长度 |
|---|---|
| c=5   | 762B |
| c=8   | 917B |
| c=74  | 1105B |
| c=218 | 1120B |
| c=312 | 1126B(饱和) |

我需要**真机抓一次这个累积器 buffer 的完整内容**,然后在 Unicorn 里 overlay 到同一地址,让 libtiny 在模拟器里自己 sign() 时正常读到真实数据,字节级正确产出 tail。

**这和之前你帮我抓的两份数据同构:**
- `docs/36_hook_requirements_for_hash_crack.md` → `docs/37_hash_probe_delivery.md`(libxyass shield hash fixture)✅
- `scratch/native_trace/cptr_snapshot_*.json`(libxyass cPtr 对象图快照)✅
- **本文档 → libtiny accumulator snapshot** ← 要做的

---

## 背景证据(可跳过)

我已经排除了 3 条试图用纯模拟器生成 tail 的路:

1. **累积器不是 sign 路径内部生成的。** 在 Unicorn 里跑 500 次 sign,`c` 计数正确递增 2→501,但 mua raw 长度只从 249 → 251(2 字节纯粹来自 `"c":<数字>` 位数加宽),tail 始终 0B。

2. **不是通过 exposed cmd 接口喂的。** 试了 `1897791419 (d3.a)` / `617278119 (encrypt)` / `-872198405 (decrypt)` / `1140071423 (d7.a)` / `730317001 (invoke)` / `-930908590 (set_timestamp)` / `1932492929 (set_bool)` / `2099694886 (feed_Object)` 共 8 个 cmd,都用真机 jadx 观察到的真实参数类型调。每个都执行了(encrypt/decrypt 甚至返回了非零对象句柄),但 mua tail 后跑 sign 依然 0B。

3. **22 个设备指纹 import(`AMediaDrm_*`, `AMediaCrypto_*`, `AMotionEvent_*`, `__system_property_*`)在 init + warmup + 多次 sign + 4 个 pthread worker 全程一次都没被调用。** 这些 import 所在的代码路径在我的模拟器里是**完全死代码**。tail 生成的代码显然就在这条"死"路径里,靠:
   - 真实 Activity lifecycle 事件触发(我们没 Android 运行时)
   - 真实 sensor / 触摸事件流(没物理硬件)
   - 真实 DRM 证书读取(没 Widevine)
   - 真实 system property 值(stub 成 0)

所以唯一还符合"Unicorn 黑盒跑 ELF"大方向的路,就是**把真机上跑出来的累积器 buffer 状态 overlay 进 Unicorn**。libtiny 的 sign() 代码一行不改,在 Unicorn 里原样跑,只是它读累积器的时候看到的是你 dump 下来的真机字节。

---

## 具体 Hook 需求

### 🔴 P0 — Hook A: 定位累积器 buffer

从我这边的 Unicorn 观察,累积器 buffer 有几个**强候选**,但我不能 100% 确定哪个是主 buffer(Unicorn 里这些地址都是 BumpAllocator 分的,和真机不同):

1. **6 MB 大 buffer** `sz=6155424` 从 `libtiny+0x548368` 的 malloc 分配,**只在首次 sign 时分配一次**。强候选主累积器 workspace。
2. **16 × 220B 元数据表** 从 `libtiny+0x5547b4`,每次 sign 分配 16 个固定大小结构,内容开头是 `0f 00 00 00 00 00 00 00 01 00 00 00 02 00 00 00 ...`(0xF + 0..15 序列)。强候选"设备指纹条目模板"。
3. **pre-base64 工作 buffer** `sz=384` 或 `528` 从 `libtiny+0x06df7c`,每次 sign 重新分配。这些是临时 buffer,不是累积器本身,但它们的大小是真机 vs emulator 唯一差异点 —— 真机这里 alloc 应该更大以容纳 "JSON + tail"。

**Hook 任务:** 在 libtiny 的 `malloc` 调用上挂 hook,dump 每次 sign(尤其是前 5-10 次)时的全部 malloc 调用 `(size, return_addr, caller_LR)`,定位出:
- 哪个 alloc 是容纳最终 mua raw bytes 的 buffer(size ≥ 1058B,即 JSON 296B + tail 762B+)
- 这个 buffer 的**真机 virtual address**
- 这个 buffer 的**偏移**(相对 libtiny base,如果它是 static/bss 的话)

**Dump 格式** (JSON lines):
```json
{
  "event": "malloc_call",
  "sign_iteration": 1,                // 第几次 sign
  "libtiny_base": "0x7e3c0000",       // 真机 libtiny load base
  "caller_lr_offset": "0x06df7c",     // 调用 malloc 的代码位置相对 libtiny base 的 offset
  "requested_size": 1280,             // r0 参数
  "returned_addr": "0xf5b48020"       // malloc 返回的堆地址
}
```

dump 至少前 5 次 sign 的全部 malloc 记录,我会在里面找 ≥ 1058B 且 caller_lr_offset 和 Unicorn 里能对上的那一个。

### 🔴 P0 — Hook B: 在 mua 生成瞬间抓 buffer 完整内容

一旦 Hook A 帮我定位了主 buffer,接下来需要在 **sign() 即将调 NewStringUTF 产出最终 mua 字符串的瞬间**,dump 这个 buffer 的完整字节内容。

从我的 Unicorn 追踪,NewStringUTF 调用点在 `libtiny+0x094553`(调用后 LR)附近。Hook 这条指令,**在调用前**:

```json
{
  "event": "mua_buffer_pre_newstring",
  "sign_iteration": 5,
  "libtiny_base": "0x7e3c0000",
  "c_counter": 5,                      // 从 mua 的 JSON "c":N 读
  "buffer_addr": "0xf5b48020",         // Hook A 定位到的那个 addr
  "buffer_size_bytes": 1058,           // 读到的实际字节数
  "buffer_content_hex": "..."          // 全部 1058 字节的 hex
}
```

至少抓**连续 26 次 sign**(和 docs/37 的 regression pair 数量一致),让我能验证 overlay 后累积器的演进是不是和真机一致。每次 sign 一条 jsonl 记录。

**关键:** 每次 sign 之前,记录当前 buffer 内容的 **diff**(相对上一次)。这样我能看到累积器每次推进了多少字节、推进在什么位置。如果是环形缓冲,能看到环绕。

### 🟡 P1 — Hook C: dump .bss / 持久状态

libtiny 可能还在 `.bss` 或某个全局静态区保存一份累积器种子状态(install-stable)。帮我 dump:

- `libtiny.so` 的 `.bss` 前 64KB(如果 .bss 小于 64KB 就全 dump)
- `libtiny.so` 的 `.data` 前 64KB

这些是 init-time 就写好的,跨请求稳定。我可以在 Unicorn 里 ctor 跑完后 overlay 这些区域。

```json
{
  "event": "bss_snapshot",
  "libtiny_base": "0x7e3c0000",
  "section": ".bss",
  "offset_from_base": "0x5c3000",
  "size": 0x10000,
  "content_hex": "..."
}
```

### 🟡 P1 — Hook D: 观察线程

libtiny 启动时 `pthread_create` 4 个后台线程。从我观察,thread handler 在 `libtiny+0x1672ad` × 3 和 `libtiny+0x1bd589` × 1。这些线程在真机上跑的到底是什么?

Hook 每个 thread 的 `start_fn`,dump:
- 线程启动时的 r0(arg) 指向的结构体前 0x40 字节
- 线程**第一次调 malloc 的位置**(通常是线程本地状态初始化)
- 线程**第一次 read/write 到 Hook A 定位的主 buffer** 的位置 + 访问类型

这帮我定位"累积器是不是被后台线程写入的",以及在哪个代码 offset 被写。

---

## 交付物

一个 tar.gz 包含:

1. `libtiny_malloc_trace_YYYYMMDD_HHMMSS.jsonl` — Hook A 前 10 次 sign 的全部 malloc 记录
2. `libtiny_mua_buffer_snapshot_YYYYMMDD_HHMMSS.jsonl` — Hook B 连续 26 次 sign 的 buffer 完整内容
3. `libtiny_bss_snapshot_YYYYMMDD_HHMMSS.bin` + `libtiny_data_snapshot_YYYYMMDD_HHMMSS.bin` — Hook C 的 raw 段
4. `libtiny_threads_trace_YYYYMMDD_HHMMSS.jsonl` — Hook D 的线程行为
5. `README.md` — 真机环境信息(Android 版本、设备型号、xhs app 版本、libtiny.so sha1、捕获时的账号 session_id)

目标大小估算:~10-50 MB(bss snapshot 占主要)

---

## 我拿到数据之后怎么用

伪码:

```python
# unicorn/libtiny_signer.py 里加一个 snapshot loader
class LibTinySigner:
    def __init__(self, snapshot_path=None):
        self._setup()  # 原样
        if snapshot_path:
            self._overlay_snapshot(snapshot_path)

    def _overlay_snapshot(self, path):
        snap = load(path)
        # 1. Overlay .bss 和 .data
        self.uc.mem_write(self.lib.base + 0x5c3000, snap["bss_content"])
        # 2. 分配一个 buffer(同大小)并把初始累积器内容写进去
        accum_addr = self.alloc.alloc(snap["buffer_size"])
        self.uc.mem_write(accum_addr, snap["initial_buffer_content"])
        # 3. 需要把累积器地址告诉 libtiny —— 这里可能需要一个小 JNI/内存 hook
        #    把 libtiny 内部引用这个 buffer 的指针改写成 accum_addr

    def sign(self, method, url, body):
        # 原样跑 — libtiny 在 Unicorn 里自己从我们 overlay 的 buffer 读写
        ...
```

验证:跑 `scratch/test_header_diff_apr13.py`,看 x-mini-mua 是不是和真机 capture 字节一致。26 连续 sign 的 buffer 演进应该和真机一致。

---

## 优先级

**必须(没这个下轮过不去):** Hook A + Hook B
**强烈建议:** Hook C(没有的话 overlay 可能不完整,ctor 跑出来的全局状态和真机不一致)
**Nice to have:** Hook D(帮我理解 tail 怎么被写的,不影响 replay)

---

## 环境注意

- 用 LSPosed 而不是 Frida(`memory:project_xhs_capture_approach` 说过 Frida 在这个 Pixel 6 Android 15 上是死路)
- xhs-capture LSPosed 模块在 `lsposed/xhs-capture/`
- libtiny.so 在 app 进程里,uid 10329
- 真机 load base 不同于我的 Unicorn(我是 0x40000000),都按 offset 算
- 记录的 session 尽量**新**,越接近抓取时间越好,和我当前 fixture (`scratch/native_trace/hash_fixture_20260415_*.jsonl`) 同一会话最好

---

## 目标

拿到这些数据后,我会:
1. 在 `unicorn/libtiny_signer.py` 里加 `accumulator_snapshot` 参数
2. sign() 前 overlay bss + .data + 初始累积器 buffer
3. 跑 `scratch/test_header_diff_apr13.py` 验证 mua 字节一致
4. 跑真机 write 端点(note CRUD)确认 406 消失

如果 1058B replay 能通过读端点,那至少能证明 shield + mua 全对,剩下 write 端点的 406 就只能是 server-side 风控/时间戳/其他环节的问题,不再是模拟器层。
