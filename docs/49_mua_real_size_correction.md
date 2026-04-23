# 2026-04-18 mua 真实大小纠正 + t 字段缺失发现

## 重大发现 (纠正之前所有 memory 记录)

**memory `mua_binary_tail_missing` 的"1058B"数据是错的**。

从 `lsposed/xhs-capture/captures/xhs_fresh_install_20260418_105925.log` 实测真机 mua:

```
x-mini-mua 总长 = 1548B
  parts = [458 (JSON_b64), 1088 (tail_b64), 0 (trailing .)]
```

Base64 decode:
- JSON = 343B
- tail = 816B

## 和我们的差距

| 维度 | 我们 | 真机 | 差 |
|---|---|---|---|
| mua total | 1165B | 1548B | **-383B** |
| JSON (decoded) | 296B | 343B | -47B |
| tail (decoded) | 576B | 816B | **-240B** |

**我们比真机短 383B**,不是之前 memory 说的"多 107B"。方向完全反了。

## JSON 字段 diff

### 真机 JSON (343B)
```json
{"a":"ECFAAF01","c":2,"k":"<64hex>","p":"a","s":"<128hex>",
 "t":{"c":0,"d":0,"f":0,"s":4098,"t":0,"tt":[]},
 "u":"<40hex>","v":"2.9.55"}
```

### 我们 JSON (296B)
```json
{"a":"ECFAAF01","c":2,"k":"<64hex>","p":"a","s":"<128hex>",
 "u":"<40hex>","v":"2.9.55"}
```

**缺失 `"t"` 对象**,少 47B。t 是 libtiny 内部 tracker 子模块状态 (tt = tracker 事件列表)。

## 根因: libtiny tracker 子模块未初始化

libtiny 输出 mua 时,内部会检查每个模块状态。如果 tracker 模块有 state → 序列化到 JSON 的 `t` 字段。我们 unidbg 里这个模块没被激活 → 无 t 字段 → JSON 短 47B。

现有 `XhsCombinedSigner.initialize()` 里 15 个 extra init cmd 调用,都执行但无可见效果 (register_app 返 null)。tracker 可能需要特定 activity lifecycle cmd 或额外参数。

## tail 240B 差距

更大的问题: tail decoded 576B vs 真机 816B = **缺 240B**。

memory `mua_rolling_accumulator` 说 tail 是 state-ful rolling accumulator。240B 缺失可能:
- libtiny `.tistore` 状态不对 (真机 cache 可能累积)
- 缺某个固定 state 初始化 cmd
- `ks.sr0` 4028B 内容被 libtiny 消化时触发更长 state

## 修复路线

1. **激活 tracker 模块** → 获得 t 字段 (+47B)
2. **累积 tail accumulator state** → 增加 240B → mua 达 1548B
3. **不在 fake_rootfs 加内容** (不是内容不够,是模块初始化逻辑不对)

## Why + How to apply

**Why**: 之前 memory 估算真机 mua 1058B 导致"我们过长 107B"错误结论,从而走向"裁 rootfs"歪路。实测真机 1548B,我们**短 383B**,方向完全反。

**How to apply**:
- 任何 mua 长度比较必须先从 capture log 实测真机真实长度
- memory note 中 mua 相关数字建议重新校准
- 下次继续: libtiny tracker 子模块激活 → 弥补 47B JSON + 伴随 240B tail state
