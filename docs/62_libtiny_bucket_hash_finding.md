# 2026-04-18 EOD6 libtiny bucket hash 在 unidbg 单桶化 — 172B 真根因

## 关键实验 (multi_url_v3.log)

MuaTailProbeTest `MULTI_URL=1` 循环 8 个不同 URL × 3 轮 = 24 sign 调用:

```
URL[0] = /api/sns/v3/user/me?...
URL[1] = /api/sns/v3/system_service/flag_exp?...
URL[2] = /api/sns/v2/system_service/config?...
URL[3] = /api/sns/v1/system/device_type?...
URL[4] = /api/sns/v1/user/verify/resources/pag
URL[5] = /api/sns/v10/user/userfeed?...
URL[6] = /api/sns/v3/user/followings
URL[7] = /api/sns/v3/trade/search
```

实测 unidbg 输出:
```
iter 0 URL[0] c=2    iter 8 URL[0] c=10   iter 16 URL[0] c=18
iter 1 URL[1] c=3    iter 9 URL[1] c=11   iter 17 URL[1] c=19
iter 2 URL[2] c=4    iter 10 URL[2] c=12  iter 18 URL[2] c=20
iter 3 URL[3] c=5    iter 11 URL[3] c=13  iter 19 URL[3] c=21
iter 4 URL[4] c=6    iter 12 URL[4] c=14  iter 20 URL[4] c=22
iter 5 URL[5] c=7    iter 13 URL[5] c=15  iter 21 URL[5] c=23
iter 6 URL[6] c=8    iter 14 URL[6] c=16  iter 22 URL[6] c=24
iter 7 URL[7] c=9    iter 15 URL[7] c=17  iter 23 URL[7] c=25
```

**全局单调 c=2..25**, 同时 **k 字段全 iter 相同**。

真机对应 (docs/56):
```
mua #14 URL_X c=9    ← first t field
mua #15 URL_Y c=6    ← 不同 URL, 不同 counter
mua #16 URL_X c=10   ← URL_X 继续累
mua #17 URL_Z c=11   ← 另一 URL_Z 到 c=11
```

真机 c 值重复 + 跳跃明显是 per-URL 独立 counter。

## 诊断

libtiny 有 bucket map (内部 HashMap<BucketKey, Bucket>)。BucketKey 大概率是 `hash(host + path)` 或类似。

**unidbg 端 bucket hash 函数退化**: 所有 URL hash 到同一 key → 只有一个 bucket → c 单调全局。

猜测原因:
- bucket hash 依赖某个 .bss slot / global state 未正确 init
- 或依赖某个 system prop / env var 我们没 mock
- 或 OLLVM 加密的 hash 种子 (magic constant) 在 unidbg 被当 0

## 对 t 字段的影响

真机 t 字段在 **某 bucket 的 c ≥ 9** 时首次出现。我们 unidbg 只有 1 个全局 bucket, 哪怕 c 到 25 也不激活 t。

**可能的触发规则**: `if (bucket_count > 1 && any_bucket.c >= 9)` ——多桶 AND 阈值。单桶状态下条件永远不满足。

## 下次攻击点

1. **定位 libtiny 的 bucket hash 函数**: 在 sign cmd (-1750991364) 内部的 dispatch 路径里, 找 `HashMap.hashCode` 或 STL `std::unordered_map` 的 hash 计算
2. Hook 那个 hash 函数,看 8 个不同 URL 各自算出的 key 值是多少
3. 如果 8 个 URL key 全 collide 到 0 或同值, 找 hash 函数的种子 / state 来源
4. 补齐那个种子, 期待 per-URL 不同 bucket → t 字段激活

## 今日前进清单

- ✅ d7.a crash 修复 (docs/61 真机 shadowhook + code_hook 注入 r2)
- ✅ 46 次 d7.a + cptr 真 populate bucket
- ✅ 反证 docs/57 假设 (cptr ≠ mua state 源)
- ✅ 禁用触发 ConcurrentModificationException 的 -930908590 / 0xafd151f7 cmd
- ✅ **锁定新 ceiling**: libtiny bucket hash 全 URL collide → 单桶 → 无 t 字段 → 短 172B

## Why / How to apply

**Why**: 连续 4 天把 unidbg 黑盒推到 libtiny 内部桶机制层面, 172B gap 的根因从最初"缺 d7.a + cptr" 深入到 "bucket hash 函数种子没对齐"。d7.a 修好但 mua 未增, 是因为 d7.a 走 xyass 的 cptr 路径, 和 libtiny mua 的桶是两条独立逻辑。

**How to apply**:
- 默认跑 unidbg 必带 `FIX_D7_EOR` hook + `D7_REPS=46`, 但别指望它自动破 2/5 ceiling
- 后续 mua 长度调试, 先 multi-URL 测 c 是否 reset — 没 reset 就是 bucket hash 问题
- `-930908590` 和 `0xafd151f7` 不要默认调, 需时显式 env var 开
