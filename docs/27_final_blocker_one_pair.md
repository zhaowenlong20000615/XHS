# 最后阻塞:1 行 JSON 即可破解全部 shield 签名

**日期**: 2026-04-14
**状态**: 静态分析 100% 完成,运行时数据 95% 完成,**只缺一对配对数据**

---

## 当前管线状态

```
Step 1: canonicalize          ✅ path + query + xy-platform-info  (docs/25)
Step 2: inner_hash            ❌ canonicalize → 16B data_in        ← 唯一未知
Step 3: shield_tail = data_in XOR DEVICE_MASK_16B  ✅  (docs/26)
Step 4: shield = device_prefix(84B) || shield_tail(16B)  ✅
```

只剩 Step 2 的 inner_hash 函数没确定。

---

## 需要另一个窗口提供的数据

### 🔴 必需(阻塞 inner_hash 破解)

**1 行 JSON**,同一台设备、同一次请求、同一个 ctx 实例内:

```json
{
  "canonicalize_hex": "<op_update 所有 raw_data 按顺序拼接>",
  "hmac_b64_input_hex": "<紧接着同 tid/ctx 的 hmac_b64 entry 16 字节 data>"
}
```

**采集方法**(已有 hook,只需改输出聚合逻辑):

1. 每个 `ctx_addr` 维护一个 buffer
2. 收到 `op_update ENTRY` → 把 `raw_data[:data_len]` append 到该 ctx 的 buffer
3. 收到 `op_final ENTRY` → 标记该 ctx 的 canonicalize 已完成
4. 收到 `hmac_b64 ENTRY` → 如果 tid 匹配且 ms 间隔 < 50ms,输出一行:
   ```json
   {"canonicalize_hex": <buffer.hex>, "hmac_b64_input_hex": <data.hex>}
   ```
5. 输出后清空该 ctx buffer

**数量**: **1 对就够**,3 对最稳。

**用途**: 拿到后立刻跑下面的 brute force,~10 秒确定 inner_hash 是哪一种:
- `MD5(canonicalize)`
- `SHA1(canonicalize)[:16]`
- `HMAC-MD5(key1, canonicalize)` / `HMAC-MD5(key2, canonicalize)`
- `HMAC-SHA1(key, canonicalize)[:16]` 各种 key 候选
- 从 `ctx_pre[0:20]` 的 precomputed HMAC-SHA1 continuation

---

### 🟡 可选(锦上添花,不阻塞 shield)

#### 选项 A:其他 header_enum 的同类配对

目前 `shield_pairs.jsonl` 的 44 条 hmac 记录全部是 `header_enum=4`,对应 shield。

`x-mini-sig`(32 hex = 32 字节)和 `x-mini-s1`(变长 base64)走的是**同一 libxyass 入口**但 `header_enum` 不同(预期 5/6/7/8)。

如果能抓到 enum=5/6/7/8 的 `(canonicalize, data_in)` 配对,就能验证:
- 它们是不是同一 inner_hash + 不同 DEVICE_MASK?
- 还是不同 inner_hash(比如 SHA-256[:32] for sig)?

破解后 → **一次性搞定全部 4 个 mini 头**,而不仅仅是 shield。

#### 选项 B:DEVICE_MASK 的来源

目前 `DEVICE_MASK = 95d17cdfa2bb91e9947b3b485623f7bb` 必须从已捕获的一对 (data_in, shield_tail) XOR 恢复。

如果想做到**全新安装零捕获冷启动**(完全不依赖 mitm 一次抓包),需要找到 mask 怎么生成的。

调查路径:
1. hook libxyass 的 `JNI_OnLoad` + `.init_array` 构造函数(2 个,已通过静态分析定位)
2. 在构造期间监控对 `__system_property_get` / `open` / `read` 的调用
3. 重点看是否读取 SharedPrefs xml 文件、Android KeyStore alias、或 `/data/data/com.xingin.xhs/files/*`
4. 把读到的 16 字节(或可派生出 16 字节的源数据)dump 出来

---

## 不需要的数据

- ❌ **更多 shield_pairs**:15 对已足够确认 XOR 公式
- ❌ **更多 ega.f.j 样本**:那是 Tiny SDK RSA-JWT 路径,跟 libxyass shield 完全无关
- ❌ **hmac_b64 EXIT hook**:已知 output = input XOR mask,exit 是冗余的
- ❌ **ctx 内部 dump**:ctx[0:40] 是 precomputed HMAC state,ctx[40:64] 是固定 init magic,已经全部分析完
- ❌ **更多 native trace dump**:只要拼接逻辑改对,1 次小请求就能产生一行有用数据

---

## 拿到 1 行数据后我会做什么

```python
import json, hashlib, hmac
pair = json.loads(input())
canon = bytes.fromhex(pair['canonicalize_hex'])
target = bytes.fromhex(pair['hmac_b64_input_hex'])

K1 = b'9190807'
K2 = b'aa293284-0e77-319d-9710-5b6b0a03bd9c'

candidates = {
    'md5(canon)':         hashlib.md5(canon).digest(),
    'sha1(canon)[:16]':   hashlib.sha1(canon).digest()[:16],
    'hmac-md5(k1,canon)': hmac.new(K1, canon, 'md5').digest(),
    'hmac-md5(k2,canon)': hmac.new(K2, canon, 'md5').digest(),
    'hmac-sha1(k1)[:16]': hmac.new(K1, canon, 'sha1').digest()[:16],
    'hmac-sha1(k2)[:16]': hmac.new(K2, canon, 'sha1').digest()[:16],
    'md5(k1+canon)':      hashlib.md5(K1+canon).digest(),
    'md5(k2+canon)':      hashlib.md5(K2+canon).digest(),
    'md5(canon+k1)':      hashlib.md5(canon+K1).digest(),
    'md5(canon+k2)':      hashlib.md5(canon+K2).digest(),
    'md5(k1+canon+k2)':   hashlib.md5(K1+canon+K2).digest(),
    'md5(k2+canon+k1)':   hashlib.md5(K2+canon+K1).digest(),
}
for name, val in candidates.items():
    if val == target:
        print(f'★ MATCH: inner_hash = {name}')
```

如果以上都不中,就上 precomputed HMAC-SHA1 continuation
(`scratch/ghidra_work/verify_hmac_sha1_hypothesis.py` 已写好,直接套用)。

---

## 完成后能做什么

```python
from xhs_device_pin_signer import DeviceSnapshot, XhsSigner

# 一次性 bootstrap (从任意一次 mitm 抓包)
snap = DeviceSnapshot.from_mitm_request(captured_headers)
snap.shield_mask = bytes.fromhex(captured_data_in) ^ shield_tail  # 16B

signer = XhsSigner(snap)

# 之后就可以离线签任意请求
headers = signer.sign('GET', '/api/sns/v3/note/feed?cursor=xxx', body=b'')
# headers['shield'] 直接可用
```

完整 5 步管线全部 Py 实现,4 个 mini 头(shield + 至少一个其他)端到端可签发。

---

## 总结

**1 对 `(canonicalize_hex, hmac_b64_input_hex)` 配对 = 整个 shield 签名管线破解完毕**。
其他都是锦上添花。
