# cPtr Snapshot v3 — 追踪 shield prefix 中 4 个缺失字节

**给 xhs-capture 窗口的增量需求**

## v2 的结果 + 验证

v2 snapshot 已经让 Unicorn 端到端跑通 shield 流水线。对照真机实际抓包:

```
真机 shield prefix[0..84]:
  5d800040 00400000 00100000 05300000 05335161 1ed311b5 21b0fdfd
  cfaa08b3 a5286993 b456be94 6e37f0f7 5e15e44a a139486b 99db46f4
  89df8aae 758cfc32 bd5997ed 8a533100 c4b4363d a64eaf4d f79348fb

emulator shield prefix[0..84]:
  5d800040 00400000 00100000 05300000 05335161 1eddde1f d1b0fdfd
                                               ^^^^^^^^^^^^
                                               只有这 4 个字节不对
```

**80/84 字节 byte-exact,仅位置 21-24 不对:**

| pos | 21 | 22 | 23 | 24 |
|---|---|---|---|---|
| 真机 | d3 | 11 | b5 | 21 |
| 我们 | dd | de | 1f | d1 |

这 4 个字节是 **install-stable**(同一 install 里对不同 URL 签名都得到一样的值),所以它们从**某个真机上被初始化、我们没捕获**的 per-install 状态里来。

## shield swap 实验证明了 4 字节差异是 blocker

- 用真机抓的 shield 打 `/api/sns/v4/note/user/posted` → **200 OK + 真实笔记数据**
- 用完全相同的 headers,**仅把 shield 换成我们 Unicorn 生成的** → **406 rejected**

server 对这 4 字节是敏感的。我们必须让它们也字节级对上。

## v2 snapshot 里缺什么

v2 抓了这些:

| 内容 | 大小 | 我们读回来 |
|---|---|---|
| cPtr 主结构 | 512B | 前 68B 有效(后面是相邻堆的垃圾) |
| `0x4224ac70` (cPtr+0x18 指向的堆对象) | 256B | **正常,含 ctx_pre** |
| `0xd6fc0000` (cPtr+0x54 指向) | 256B | **全零 — 可疑!** |
| key2.data (bss+0x7df18) | 64B | 正常,deviceId |
| bss snapshot `+0x7df00..+0x7e000` | 256B | 正常 |

v2 snapshot 里 `0xd6fc0000` 这块是全零 —— 要么真机上它就是 0,要么我们读到了不对的地方。`0xd6fc0000` 这地址看上去不像普通 heap(太对齐了),可能是某个 .data / .rodata 区的指针。

## v3 要追加的采集

### 1. 扩大 cPtr 扫描范围,递归跟更多指针

v2 只扫了 `cPtr[0..0x60]` 里找指针。请扩到 **`cPtr[0..0x100]`**,再把新找到的指针都抓下来(每个 256B)。

```javascript
// v3: scan 0x100 bytes, up from 0x60
for (let off = 0; off < 0x100; off += 4) {
    const w = ptr(cPtrAddr).add(off).readU32();
    if (isPlausibleHeapPtr(w)) dumpAndRecurse(w, 256, ...);
}
```

### 2. 复查 `0xd6fc0000`,确认是不是有效指针

在 v2 里它被记录成指向 256 字节全零的堆对象。这很可疑。请在 Frida hook 里加这段诊断,看这个地址的真实情况:

```javascript
const p54 = ptr(cPtrAddr).add(0x54).readU32();
console.log(`cPtr+0x54 = 0x${p54.toString(16)}`);

// 检查这个地址落在哪个 region
const rng = Process.findRangeByAddress(ptr(p54));
console.log(`  in region: ${rng ? rng.base + '-' + rng.base.add(rng.size) + ' ' + rng.protection + ' ' + rng.file?.path : 'unmapped'}`);

// 读前 64 字节
try {
    const b = ptr(p54).readByteArray(64);
    console.log(`  bytes: ${Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('')}`);
} catch (e) { console.log(`  read err: ${e}`); }
```

把这段的输出附在 JSON 的 `diagnostics` 字段里。

### 3. 抓 libxyass 的完整 .data + .bss 段

v2 只抓了 `+0x7df00..+0x7e000` 256 字节 bss。请改为抓 **整个 .data + .bss 段**。用 Frida 的 `Process.enumerateRanges` 找到 libxyass 的 rw- 映射区:

```javascript
const mod = Process.findModuleByName("libxyass.so");
const ranges = Process.enumerateRangesSync({protection: 'rw-', coalesce: false})
    .filter(r => mod && r.base.compare(mod.base) >= 0 &&
                  r.base.compare(mod.base.add(mod.size)) < 0);
console.log(`libxyass rw- ranges: ${ranges.length}`);
for (const r of ranges) {
    console.log(`  ${r.base}..${r.base.add(r.size)} (${r.size} B)`);
    out.data_segments.push({
        base: r.base.toString(),
        size: r.size,
        hex: r.base.readByteArray(r.size) /* → hex */
    });
}
```

典型 `libxyass.so` 的 rw- 段会是几十 KB(估计 20-100 KB)。全抓下来,我这边能搜那 4 个字节出自哪。

### 4. 抓 libxyass 持有的 pthread-local 状态(可选但推荐)

libxyass 可能用 `pthread_key_create` 把 per-install 状态藏在 TLS 里。TLS 不在常规 bss 里。Frida 没直接 API 读其它线程的 TLS,但可以间接:

```javascript
// 找所有指向 libxyass text 的函数调用位置的 thread
const pthreadKeys = [];
// 最简单:扫 libxyass .data 段里所有 "像 key" 的 u32 (很小的整数 < 256)
// 然后 hook pthread_getspecific 看真实调用。
// 如果太复杂跳过,靠 v3 第 3 条 (bss + data) 覆盖大多数情况。
```

**如果第 3 条(完整 .data + .bss)已经实现,TLS 这步可以跳过。**

### 5. 搜索目标字节 `d3 11 b5 21`(诊断辅助)

既然我们知道真机 shield 中这 4 字节的具体值是 `d3 11 b5 21`,在 snapshot 采集之后在 Frida 端顺带扫一下 libxyass 映射内所有 `rw-` 页里这个字节模式的出现位置:

```javascript
const TARGET = [0xd3, 0x11, 0xb5, 0x21];
for (const r of ranges) {
    try {
        const b = new Uint8Array(r.base.readByteArray(r.size));
        for (let i = 0; i <= b.length - 4; i++) {
            if (b[i]===TARGET[0] && b[i+1]===TARGET[1] && b[i+2]===TARGET[2] && b[i+3]===TARGET[3]) {
                console.log(`★ found d311b521 at ${r.base.add(i)} (rel +0x${(r.base.add(i).sub(mod.base)).toString(16)})`);
                out.found_target.push({addr: r.base.add(i).toString(), relative: "0x" + r.base.add(i).sub(mod.base).toString(16)});
            }
        }
    } catch (e) {}
}
```

**这一步极其有用**:如果它在 libxyass 某个已知位置里找到了 `d3 11 b5 21`,我立刻就知道 shield 这 4 字节出自哪个偏移,v3 就完成了。

## 产出格式扩展

基于 v2 的 JSON schema,v3 加几个字段:

```json
{
  "format_version": 3,
  "captured_ms": ...,
  "libxyass_base": "...",
  "cptr_addr": "0x...",
  "cptr_hex": "...",               /* 256B,比 v2 多 */
  "heap_objects": [ ... ],          /* 递归深度 2,扫 0x100 范围 */
  "data_segments": [                /* NEW: libxyass 完整 rw- 段 */
    {
      "base": "0x...",
      "size": 20480,
      "hex": "..."
    }
  ],
  "diagnostics": {                  /* NEW: 帮我们 debug 的信息 */
    "cptr_plus_54_region": "<Process.findRangeByAddress output>",
    "cptr_plus_54_bytes": "<first 64 bytes>"
  },
  "found_target": [                 /* NEW: 搜索 d311b521 的命中位置 */
    {"addr": "0x...", "relative": "0x..."}
  ]
}
```

## 产出文件位置

```
scratch/native_trace/cptr_snapshot_v3_<timestamp>.json
```

## 验收

v3 snapshot 只要满足:

- [ ] `data_segments` 存在且非空(至少一段,推荐覆盖 libxyass 所有 rw- 段)
- [ ] `diagnostics.cptr_plus_54_*` 诊断信息存在  
- [ ] `found_target` 存在(可以为空列表,但必须出现 —— 表示扫过了)

**最关键的是第 5 条**: `found_target` 里列出所有 `d3 11 b5 21` 的出现位置。哪怕只命中 1 次,我就能精确定位 shield 4 字节的来源地址。

## 一次性采集,长期受益

这 4 字节是 install-stable。v3 snapshot 采完后,我把结果写进 loader 的 per-install 常量,**以后所有 sign 请求都不需要再采集**,直到 xhs app 升级或 install 数据被清。

## 背景:shield swap 实验数据(给你看上下文)

```
测试 A — 用真机 shield 的同一 request:
  STATUS: 200
  BODY: {"code":0,"data":{"has_more":true,"notes":[{"widgets_context":"...",
        "author_name":"小红薯ujib1bq7","comments_count":13,...}]}}

测试 B — 完全相同的 headers,仅 shield 换成 Unicorn 生成的:
  STATUS: 406
  BODY: {"code":0,"success":true,"data":{}}
```

真机 shield 的 22-25 字节(我们的 0-indexed 21-24):`d3 11 b5 21`
Unicorn 生成的对应位置:`dd de 1f d1`

差异是 install-stable,和 URL / 请求内容无关。找到 `d3 11 b5 21` 在内存里的源头就能关闭这个 gap。

---

**我这边同时在做**: 反汇编 libxyass intercept 的 shield-header 构造路径,看能不能从代码层找到这 4 字节从哪个地址读出来。两路并行,哪边先定位到都行。
