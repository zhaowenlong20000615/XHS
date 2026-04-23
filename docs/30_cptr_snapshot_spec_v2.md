# cPtr Snapshot v2 — 需要递归跟指针的深度采集

**给 xhs-capture 窗口的更新需求**

## 上一版采到的东西

```
cptr_snapshot_20260414_153053.json  (1986B)
  - cptr_hex: 512 字节 ✓
  - strings: 只有 2 项 (main / main_hmac, 都是 SHORT) ✓
  - bss_snapshot: 256 字节 ✓
```

验收**没过**,但**不是你的脚本有 bug** —— 是我上一版需求写错了:我假设
`cPtr+0x18..+0x44` 是 4 个 std::string 槽,结果真机 dump 出来这些位置是
**其它类型的字段**,主要是**指针**。我的 `strings` 扫描跳过它们是对的。

## 真机 cPtr 的真实布局(来自这次 dump)

```
+0x00  086d61696e 00000000 000000    "main"      SSO std::string ✓
+0x0c  126d61696e 5f686d61 630000    "main_hmac" SSO std::string ✓
+0x18  50f5bbec                       pointer → 0xecbbf550    ★未跟
+0x1c  00000000 00000000 ...         (零,可能是 size / flags)
+0x44  74727565                       "true" 4 字节 (也许是某个字符串的
                                       short inline storage)
+0x48  0019c7ec                       pointer → 0xecc71900    ★未跟
+0x4c  581ac7ec                       pointer → 0xecc71a58    ★未跟
+0x58  050105000000e43f               可能是 float/flag
+0x60+ 乱码(超过了 cPtr 的实际大小,
        开始读到相邻堆对象的 C++ 符号表了)
```

**三个指针我们一个都没 dump**。populate 路径里要用的 state 就在这三个指针指向
的堆对象里。

## v2 需要补充采集的东西

### 1. 跟 `cPtr` 里的指针

扫 `cPtr[0..0x60]` 每 4 字节一个 word:

```python
for off in range(0, 0x60, 4):
    w = *(u32*)(cPtr + off)
    if is_plausible_heap_pointer(w):
        dump(w, size=256)
```

`is_plausible_heap_pointer(w)` 的判定:

- `w` 在真机进程的 heap 区间内(通常是 `0xc0000000..0xf0000000` 这一大段,
  或者用 `Process.enumerateRanges('rw-')` 查表判断是否落在 `[heap]` 或
  anonymous private 区)
- `w` 可读(用 `Memory.readByteArray(ptr(w), 4)` 包 try/catch 就行)
- `w` 不等于 `cPtr` 本身(避免自指)

对每个命中的指针,dump **256 字节**(保守值,多抓一点)。

### 2. 递归跟到 **2 层深度**

对每个 dump 下来的堆对象,再扫它里面的 4 字节 word,同样判定是否是堆指针,
是的话也 dump。深度限制在 **2 层**(cPtr → level 1 → level 2),避免指针图
无限展开。

**去重**:用 `Set<address>` 保存已 dump 的地址,不要重复 dump 同一个对象。

### 3. 已知的 3 个关键指针(保底)

就算上面的启发式漏掉了,请**显式**把这 3 个地址 dump 下来(各 256 字节):

- `*(cPtr + 0x18)` = 0xecbbf550 (这次的值,下次抓会变)
- `*(cPtr + 0x48)` = 0xecc71900
- `*(cPtr + 0x4c)` = 0xecc71a58

### 4. 跟 bss 里 key2 std::string 的 data_ptr

bss snapshot 里 `+0x10` 的 LONG std::string 指向 `0x4d34ea90`(deviceId 的
36 字节)。**请把这块数据也 dump 下来**(36 字节就够,但保险起见 dump 64):

```python
key2_data_ptr = *(u32*)(libxyass_base + 0x7df10 + 0x08)   # = 0x4d34ea90
dump(key2_data_ptr, size=64)
```

### 5. 确定 cPtr 的真实大小

我们抓 512 字节太多,后面读到了相邻对象。想确认 cPtr 的精确 size,可以读
malloc metadata:

- Scudo / jemalloc 在 user pointer 前面有一个 header
- 尝试 `Memory.readU32(ptr(cPtr).sub(8))` 或 `sub(4)`,看有没有合理的 size 字段
- 或者用 `Process.findRangeByAddress(ptr(cPtr))` 查它所在的映射

如果不好弄**就跳过这个**,我这边根据 dump 出来的 cPtr 内容(看到第一个不像
有效字段的 word 就认为是边界)自己切。

## 产出格式(扩展 JSON)

在原来的 JSON 基础上加一个 `heap_objects` 字段:

```json
{
  "format_version": 2,
  "captured_ms": ...,
  "libxyass_base": "...",
  "cptr_addr": "0xecebe410",
  "cptr_size": 512,
  "cptr_hex": "...",
  "bss_snapshot": { ... },
  "strings": [...],
  "heap_objects": [
    {
      "addr": "0xecbbf550",
      "size": 256,
      "hex": "...",
      "ref_path": ["cPtr+0x18"]
    },
    {
      "addr": "0xecc71900",
      "size": 256,
      "hex": "...",
      "ref_path": ["cPtr+0x48"]
    },
    {
      "addr": "0xecc71a58",
      "size": 256,
      "hex": "...",
      "ref_path": ["cPtr+0x4c"]
    },
    {
      "addr": "0x4d34ea90",
      "size": 64,
      "hex": "...",
      "ref_path": ["bss+0x7df10 key2.data"]
    },
    /* level-2 objects */
    {
      "addr": "0x...",
      "size": 256,
      "hex": "...",
      "ref_path": ["cPtr+0x18", "+0x10"]
    }
  ]
}
```

`ref_path` 记录怎么一层层找到这个对象的,方便我 debug。

## 建议的 Frida 脚本骨架

```javascript
const dumped = new Set();
const heapObjects = [];
const MAX_DEPTH = 2;

function isPlausibleHeapPtr(w) {
    if (w < 0xa0000000 || w > 0xfe000000) return false;
    try {
        Memory.readU8(ptr(w));  // probe readable
        return true;
    } catch (e) { return false; }
}

function dumpAndRecurse(addr, size, refPath, depth) {
    const addrHex = addr.toString(16);
    if (dumped.has(addrHex)) return;
    dumped.add(addrHex);
    let bytes;
    try {
        bytes = ptr(addr).readByteArray(size);
    } catch (e) { return; }
    heapObjects.push({
        addr: "0x" + addrHex,
        size: size,
        hex: /* byte array → hex string */,
        ref_path: refPath
    });
    if (depth >= MAX_DEPTH) return;
    // scan for pointers
    for (let off = 0; off < size; off += 4) {
        const w = ptr(addr).add(off).readU32();
        if (isPlausibleHeapPtr(w)) {
            dumpAndRecurse(w, 256,
                refPath.concat([`+0x${off.toString(16)}`]), depth + 1);
        }
    }
}

Interceptor.attach(INITIALIZE_ADDR, {
    onLeave(retval) {
        const cPtr = retval.toInt32() >>> 0;
        dumpAndRecurse(cPtr, 512, ["cPtr"], 0);
        // explicit force-dump of key2 data from bss
        const key2DataPtr = LIBXYASS.add(0x7df18).readU32();  // bss +0x7df10 + 8
        dumpAndRecurse(key2DataPtr, 64,
            ["bss+0x7df10 key2.data"], MAX_DEPTH);  // no further recurse
        send({ tag: "cptr_snapshot_v2" }, JSON.stringify({
            /* ...同上, plus heap_objects */
        }));
    }
});
```

## 验收标准 v2

- [ ] `cptr_hex` (≥ 128B) — 已有
- [ ] `heap_objects` 至少 4 项:cPtr+0x18 指向的、cPtr+0x48 指向的、
      cPtr+0x4c 指向的、bss key2 的 data
- [ ] 每个 heap object 的 `hex` 非零
- [ ] 总文件大小大概会到 **8–30 KB**(level-2 递归会展开很多对象);
      如果超过 200KB 说明递归失控,`MAX_DEPTH` 太大或启发式太松

## 风险

- 堆指针启发式可能假阳性 —— 如果 dump 出来一堆无关对象,我这边会挑出真正
  需要的。无所谓。
- 递归深度 2 可能不够。如果加载进 emulator 后还缺东西,我会告诉你哪个指针
  需要再往下跟。

## 我这边的下一步

拿到 v2 快照后:

1. 写 `unicorn/cptr_snapshot_loader.py`:读 JSON,把 cPtr 和 heap_objects 分配
   到 BumpAllocator,**rewrite 所有 hex 里的指针,把真机地址映射到 emulator
   地址**(这步是关键,因为 heap addr 会变)
2. 修改 `sign.py` 的 `_prepare()`,加一个 `--snapshot FILE` 参数,加载时跳过
   `initialize()` 调用,直接用 snapshot 里的 cPtr 做参数
3. 跑 sign(),看 shield tail 是不是字节级匹配 cache signer

---

**TL;DR**: hook 对,只是没跟指针。加"递归跟 heap pointer,深度 2,带去重"
就行。大概 Frida 脚本加 30 行。
