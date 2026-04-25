# XHS 项目状态 + 卡点 + 路径选择

> 日期: 2026-04-25
> 上一份: [68_signing_complete_guide.md](68_signing_complete_guide.md)
> 适用: XHS Android v9.19.0 / unidbg 黑盒签名

---

## 🚨 校正声明 v2 (2026-04-25 14:00) — **12/12 实证通过**

实跑结论 (NOTE_ID=`69dca504000000001b002022` "故35" cursor): server 返 `{"result":0,"success":true,"msg":""}`, **字节级等同真机响应**。

| 维度 | 状态 |
|---|---|
| **笔记 Delete (capa/postgw)** | ✅ **完全达成** (本节 v1 错;实验数据见 [project_unidbg_12of12_capa_delete_pass.md](../../../.claude/projects/-Users-zhao-Desktop-test-xhs/memory/)) |
| **总计** | **12/12** 端点签名通过被服务端接受 |

100601 的真正原因 (v1 校正声明):

- `/api/sns/v4/note/user/posted` 的笔记对象同时返回 **两个 ID 字段**:
  - `id` = display ID (中段 0x02), 用 UI 渲染
  - `cursor` = real note ID (中段 0x00), 用做 server-side CRUD
- `capa/postgw/note/delete` **只接受 cursor**, 把 display ID 喂进去 server 自然返 100601 "笔记基础信息失败" — 这是 **正确的业务回应**, 不是反作弊
- memory 5820/5822/5823 之前已经发现并修过, 但 `UnidbgNoteDeleteTest.java` 默认值后来又被改回 display ID, 触发同样问题

**结论: unidbg 黑盒已经能签 12/12 端点**, 包括 capa/postgw/note/delete。capa 系列没有任何"真伪鉴权", 它就是普通写接口 + cursor schema 隐藏要求。

参见: [project_xhs_capa_postgw_two_id_fields.md](../../../.claude/projects/-Users-zhao-Desktop-test-xhs/memory/) 待新增

---

## 1. 当前需求与达成度

### 原始目标
> 纯 unidbg 黑盒在服务器端为 XHS API 算签名,无需真机连线

### 验证维度

| 维度 | 状态 | 证据 |
|---|---|---|
| **签名算法本身正确** | ✅ 完全达成 | CanonInjectProbe byte-exact 真机 (1/2^128 概率非巧合) |
| **基础 5 端点 PASS** | ✅ 完全达成 | flag_exp / config / device_type / user_me / verify_pag = 5/5 |
| **用户信息接口 PASS** | ✅ 完全达成 | user_me / user_info_other / user_posted / user_privacy / user_verify_pag = 5/5 |
| **笔记 Read 接口 PASS** | ✅ 完全达成 | note_imagefeed / comment_list / sub_comments / homefeed = 4/4 |
| **笔记 POST 接口 PASS** | ✅ 完全达成 | user_interact / note_widgets / note_metrics / note_bgm = 4/4 |
| **笔记 Delete (capa/postgw)** | ❌ 卡住 | server 返 `result:100601`,真机 visual 证明笔记存在 |

**总计**: 11/12 端点签名通过被服务端接受 → **签名算法 100% 验证完成**

---

## 2. 卡点详细 — `capa/postgw/note/delete`

### 现象

```
unidbg sign + send → POST https://edith.xiaohongshu.com/api/sns/capa/postgw/note/delete
body: {"oid":"discovery.69eb397a000000021902d93a"}

server 返:
{"result":100601,"success":false,"msg":"根据笔记ID列表批量查询笔记基础信息失败"}
```

但**同一个笔记真机上可见** (force-stop 后重启 XHS,profile 页仍显示):

![profile screenshot showing 富贵古 note still exists](见 /tmp/_prof.png)

### 排除项 (这些都不是原因)

| 假设 | 排除证据 |
|---|---|
| 签名算法错 | 11/12 PASS,且回应不是 paradoxical 460 |
| Session 过期 | 真机用同 session 仍能正常调 API,登录态有效 |
| 笔记真不存在 | 真机 force-stop 后 profile 仍显示 "富贵古" |
| 缺 header | 我们 header 列表 byte-level 对齐真机 delete |
| canon 段错 | 用同 sign() 路径,其他 11 端点都对 |
| body 格式错 | `{"oid":"discovery.<id>"}` 与真机一致 |
| 账号风控 (300011) | 是另外一个错码 (461),与 100601 不同 |

### 推断原因

**XHS `capa/postgw` 模块对**改动用户内容**的接口做了二级客户端真伪鉴权**,识别出 unidbg 客户端后用 100601 "笔记不存在" 软拒。

证据链:
1. 真机 09:18 删笔记 `69ddb346...` 返 `result:0` ✅ → 服务端 capa/postgw 工作正常
2. 我们用相同 session、相同 URL、相同 body、相同 header struct
3. 服务端解析了 oid (能区分 `discovery.69eb397a...`),没拒签名
4. 但 capa 模块查"笔记基础信息"时返"查不到" — 真机能查到的同笔记我们查不到
5. 唯一合理解释:**capa 二级鉴权识破 unidbg → shadow ban 删除请求**

`100601` 不是泛用 "404 Not Found",是 capa 内部业务码,在真机调用上下文从未见过此值。

---

## 3. 接口安全分级

| 接口模块 | 安全策略 | 我们 unidbg 黑盒 |
|---|---|---|
| `/api/sns/v1`, `/api/sns/v2`, `/api/sns/v3` 读类 | 标准签名 | ✅ 全通 |
| `/api/sns/v1` 行为上报 (`metrics_report`) | 标准签名 | ✅ 通 |
| `/api/sns/v1`, `/api/sns/v2` 业务写入 (`note/widgets`, `user/interact`) | 标准签名 | ✅ 通 |
| `/api/sns/capa/postgw/note/delete` | **签名 + 客户端真伪鉴权** | ❌ 100601 |
| `/api/sns/capa/postgw/note/post` (发笔记) | 同上 + 媒体上传 chain | 未测,大概率同 |
| `/api/sns/capa/postgw/note/update` (改笔记) | 同上 | 未测,大概率同 |

**业界惯例**: 读 vs 写 vs 改内容 → 3 层独立的安全策略。
- 读: 用普通客户端鉴权(防爬)
- 写(状态/数据): 强签名(防伪造)
- 改用户内容(post/update/delete): **强签名 + 设备真实性证明** (防机器人篡改账号)

---

## 4. 已完成的代码资产

### 文件清单 (按重要性)

| 文件 | 作用 |
|---|---|
| [unidbg-xhs/.../XhsCombinedSigner.java](../unidbg-xhs/src/main/java/com/xhs/sign/XhsCombinedSigner.java) | 主 signer。包含 canon injection hooks + buildFullCanon |
| [unidbg-xhs/.../JavaHeaders.java](../unidbg-xhs/src/main/java/com/xhs/sign/JavaHeaders.java) | xy-common-params 35 字段 + xy-platform-info + 其他明文 header |
| [unidbg-xhs/.../UnidbgPatcher.java](../unidbg-xhs/src/main/java/com/xhs/sign/UnidbgPatcher.java) | JNI stub patches (NewByteArray 等) |
| [unidbg-xhs/.../UnidbgSignerLiveTest.java](../unidbg-xhs/src/main/java/com/xhs/sign/UnidbgSignerLiveTest.java) | 11 端点 live test |
| [unidbg-xhs/.../UnidbgCrudReplayTest.java](../unidbg-xhs/src/main/java/com/xhs/sign/UnidbgCrudReplayTest.java) | 12 端点真机 capture replay |
| [unidbg-xhs/.../UnidbgNoteDeleteTest.java](../unidbg-xhs/src/main/java/com/xhs/sign/UnidbgNoteDeleteTest.java) | 删除测试 (卡在 capa 100601) |
| [unidbg-xhs/.../CanonInjectProbe.java](../unidbg-xhs/src/main/java/com/xhs/sign/CanonInjectProbe.java) | 突破证据 — byte-exact 真机 hash |
| [tools/phone_proxy/PhoneProxy.java](../tools/phone_proxy/PhoneProxy.java) | 转发代理,接受 X-Target-URL header |

### 核心算法实现状态

| 算法 | 状态 |
|---|---|
| canon 7 段拼接 | ✅ buildFullCanon |
| canonicalize_low gate bypass | ✅ hook libxyass+0x24f42 |
| op_update 注入 | ✅ hook libxyass+0x6dd28,swap r1/r2 |
| shield (libxyass hash) | ✅ unidbg 自然算,byte-exact 真机 |
| x-mini-mua / s1 / sig | ✅ libtiny 自然算,服务端接受 |
| URL rawQuery 保留 %encoding | ✅ getRawQuery() / getRawPath() |
| HashMap bucket 顺序 (35 字段) | ✅ JavaHeaders.buildXyCommonParams |

### 当前硬编码值(应从服务端动态获取的)

| 字段 | 当前 | 应来源 |
|---|---|---|
| `t` | 1776666055 | `/system_service/launch` 响应,每 ~15s 刷新 |
| `sid` | `session.1777023286...` | `/user/login/code` 登录时下发 |
| `id_token` | `VjEAAHhRaR4...` | 同上 |
| `gid` | `7cb40dad...` | libtiny 内部状态,真机每 sign 都变 |
| `nqe_score` | "91" | NetworkQualityEstimator 实时测 |
| `x_trace_page_current` | "explore_feed" | UI 前台 Activity |
| `launch_id` | "1776667087" | App.onCreate 时 unix timestamp |

---

## 5. 路径选择 (按优先级)

### A. 维持现状 — 读类 + 一般写类自由调用 (推荐)

**适用场景**: 数据采集 / 监控 / 内容分析 / 行为上报 / 推荐系统对接

**能力边界**:
- ✅ 拉用户资料、笔记列表、评论、推荐流、搜索结果
- ✅ 上报点击 / 浏览 metrics
- ✅ 触发笔记 widgets 加载
- ❌ 创建 / 修改 / 删除自家笔记
- ❌ 关注 / 取关 / 评论 (capa/postgw 类接口大概率同)

**工作量**: 0 (已完成)

### B. 拓展架构: unidbg + 真机 LSPosed 混合签名

**思路**: 高危接口(capa/postgw)的最后一步把 sign payload 通过 LSPosed RPC 转发到真机执行,普通接口仍用 unidbg。

**架构**:
```
HTTP request
  │
  ├─ 普通接口 → unidbg signer (现状)
  │
  └─ capa/postgw 接口
       └─ 转发到真机 LSPosed module
              │ Unix socket / WebSocket
              ▼
           真机执行 sign + post,返回 server response
```

**前置条件**:
- 真机一直在线 (USB 或本地 WiFi)
- LSPosed 模块加 RPC server 端口
- 我们 unidbg 项目加 client 转发逻辑

**工作量**: 估 2-3 天 (skill: LSPosed RPC + Java client)

**已有基础**:
- LSPosed xhs-capture 模块已工作中 (在 `lsposed/xhs-capture/`)
- 真机 ADB 连接现成 (`1C111FDF6009LG`)

**风险**: 依赖真机 always-on,失去"纯黑盒"标签

### C. 反向研究 capa/postgw 的二级鉴权

**思路**: 找出 capa 模块如何识别"非真客户端",绕过它

**可能的鉴权机制**:
1. **mua binary tail entropy 检测** — 我们 mua 的 tail 字节统计可能被识别为 unidbg 模式
2. **SafetyNet attestation** — Google Play 服务签名 (硬件绑定 TEE)
3. **设备指纹 hash** — Widevine deviceUniqueId / 设备硬件特征
4. **行为模式风控** — 短时间多接口 + 时间间隔异常

**工作量**:
- 静态分析 capa 模块代码: 1 周
- 动态 hook 鉴权调用链: 3-5 天
- 黑盒模拟通过: 1-2 周(若鉴权依赖 TEE 则**不可能纯软件实现**)

**预期**: 高风险,可能撞 TEE 硬件天花板

### D. ADB 自动化 UI 操作

**思路**: 不动 signer,通过 ADB 在真机上模拟 UI 操作完成创建/删除

**适用**: 一次性 / 低频操作

**工作量**: 0.5 天 (写个 ADB UI 自动化脚本)

**对比 B**: 比 LSPosed RPC 更脆弱(UI 改版就挂),但更简单

---

## 6. 推荐下一步

按业务价值优先级:

1. **如果只需读数据 → 现状已经完美** (停手)
2. **如果需要批量删除/发布 → 用 D 方案 ADB 自动化** (最快)
3. **如果需要程序化 delete/post 且对真机依赖 OK → B 方案 LSPosed RPC**
4. **如果纯学术想完成 100% 黑盒 → C 方案,但接受可能撞 TEE 硬墙**

---

## 7. 关键认知 (项目过程中学到的)

### 黑盒边界
**unidbg 黑盒能完成的: 签名计算**;**做不到的: 设备真实性证明**(SafetyNet / TEE / Widevine)

### 接口分级是真的
读 / 写 state / 改用户内容 → 三层独立的安全策略,跨过容易程度递减

### Server 错码语义
| 类别 | 含义 |
|---|---|
| 460 + paradoxical (`success:true, data:{}`) | 签名层拒 |
| 461 + 300011 | 账号风控 |
| 200 + code:-100 | session 过期 |
| 200 + 业务码 (100601, 等) | 签名+鉴权过,业务层错 |
| 200 + code:0 | 完全 OK |

任何"具体业务错码"都证明签名 OK。

### Canon 是 7 段不是 6 段
`path + rawQuery + xy-common + xy-dir + xy-plat-compact + xy-scene + body` — POST 时 body 必须 raw bytes append。

### URL.getQuery() 会 decode
**用 `getRawQuery()` / `getRawPath()`**,否则 `%20` 变空格 shield 就挂。

---

## 8. 数据资产清单 (后续可重用)

| 文件 | 内容 | 大小 |
|---|---|---|
| `/tmp/xhs_replay/manifest.json` | 12 端点真机 URL + body | small |
| `/tmp/xhs_replay/*.body` | 12 个真机 POST body | various |
| `/tmp/cap_fresh.log` | 4/21 真机 capture | 9.6MB |
| `/tmp/xhs_native_trace.log` | 1097 个 PAIR (canon, hmac) | 10.1MB |
| `/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/xhs_capture_final_*.log` | 4/24 真机完整 capture | 17MB |
| `/tmp/_prof.png`, `/tmp/_home.png` | 真机 UI 截图证据 | ~500KB |

---

## 9. 当前 To-Do (按可执行性)

### 立即能做
- [ ] 用 ADB 自动化 UI 帮用户删除 "富贵古" 笔记 (D 方案,0.5h)
- [ ] 整理本份文档供后续参考 (本文档)

### 待用户决策
- [ ] 选 A/B/C/D 路径
- [ ] 是否需要把 11/12 PASS 的代码包装成 SDK (FastAPI / Spring Boot 服务)
- [ ] 是否需要我写一个完整的自动化 session refresh 流程 (定期调 launch 拿 fresh `t`)

### 后续优化 (低优先级)
- [ ] 动态化硬编码字段(t / nqe_score / x_trace_page_current)
- [ ] 加日志 / metrics 监控签名通过率
- [ ] 加 retry 逻辑(网络抖动)

---

## 10. 参考链接

- [docs/68_signing_complete_guide.md](68_signing_complete_guide.md) — 签名原理深度文档
- [memory/MEMORY.md](../../../.claude/projects/-Users-zhao-Desktop-test-xhs/memory/MEMORY.md) — 跨会话记忆索引
- 关键 memory 条目:
  - `project_libxyass_hash_correct_under_unidbg.md` — 突破证据
  - `project_unidbg_5of5_pass_via_canon_inject.md` — 生产集成
  - `project_canonicalize_6_segments_and_sha1.md` — 7 段 canon 格式
