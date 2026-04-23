# XHS 请求头来源分类（jadx + 抓包交叉验证）

日期：2026-04-15
方法：jadx 反编译源码字符串搜索 + mitmproxy session 抓包 + 先前 docs/01, docs/header_algorithms 交叉核对

## 背景

以前把请求头笼统分成"libxyass 签的 / libtiny 签的 / 设备常量"。本轮用 jadx 源码 + 两份 mitm session (session1_first_capture_80apis.mitm, session2_full_usage_20260411_123810.mitm) 反查每个头的真实来源，纠正多处误判。

## 最终分类表

| 头名 | 真实来源 | 证据 | Per-request |
|---|---|---|---|
| `shield` / `x-sign` | NATIVE_LIBXYASS | XhsHttpInterceptor.java:83 → Native.intercept() → libxyass.so:0x23e54（2682B 函数）| yes |
| `x-mini-sig` | NATIVE_LIBXYASS | 同一 JNI 入口；SHA-256 hex | yes |
| `x-mini-s1` | NATIVE_LIBXYASS | 同一 JNI 入口；62B base64，magic 0x00050000 | yes |
| `x-mini-mua` | NATIVE_LIBXYASS | 同一 JNI 入口；JSON(a/c/k/p/s/u/v) + 788B 尾；session 内稳定，只有 `s` 字段随 session | session-scoped |
| `x-mini-gid` | NATIVE_LIBXYASS | 同一 JNI 入口；device-constant | no |
| `xy-direction` | NATIVE_LIBTINY | ega/f.j() 调 libtiny；返回的 Map 里与 x-mini-* 并列 | yes |
| `xy-scene` | NATIVE_LIBTINY | 同 libtiny 入口；运行期参数 | yes |
| `xy-common-params` | **JAVA_BUILT** | gqb/p.java:49-133 URL-encoded k=v 构造：platform, versionName, channel, deviceId, project_id=ECFAAF, app_id=ECFAAF01, build, sid, tz, cpu_name, device_model, overseas_channel | yes |
| `xy-platform-info` | JAVA_BUILT（**仅 /patch**）| RequestPatchInfoTask.java:36 设置 `xy-platform-info = platFormInfo`；**主 API 流量不携带此头** | no |
| `x-legacy-did` | JAVA_BUILT | r76.a "TinyInterceptor" 从本地 deviceId 注入 | device-constant |
| `x-legacy-sid` | JAVA_BUILT | r76.a；ar.d6.f11924a.A().getSessionId() | per-session |
| `x-legacy-fid` | JAVA_BUILT | r76.a；foreign ID | mixed |
| `X-B3-TraceId` | JAVA_BUILT | zlb/n0.java 用 UUID 新生成，客户端 APM trace | yes |
| `x-xray-traceid` | JAVA_BUILT | zlb/n0.java 同上，XRay trace | yes |
| `authorization` | **SERVER_PROVISIONED_PER_SESSION** | LoginUserActivateResponse.java f133874a(session) / f133875b(secure_session) → /activate 返回 → 客户端缓存 → 每次请求重放，直到下次登录 | per-session |
| `xhs-deviceid` | DEVICE_CONSTANT | 本地 android_id | no |

## 重大修正（以前错了的）

### 1. xy-common-params ≠ 服务端下发
以前一些文档把它归入"需签名后端验证"一组。**错**。jadx gqb/p.java:49-133 显示它是纯 Java URL encode，每次请求用当时的设备属性现拼，完全可自己构造，不需要逆任何 .so。之前 Unicorn 路径里还在担心它——可以忽略这担心。

### 2. xy-platform-info 只用于 /patch 端点
以前把 `platform=android&build=<int>&deviceId=<uuid>` 当作 shield canonicalize 的一部分。**这可能是个误会**：主 API（note/user/posted 这些 406 的端点）根本不发 `xy-platform-info`。需要复核 docs/25_canonicalize_format_solved.md 里的 canonicalize 公式是不是拿错端点了——是 /patch 的 canon 还是主 API 的？这直接关系 shield 逆向的 ground truth 采样是否有效。

**行动项**：静态追 XhsHttpInterceptor.java intercept() 调用处，看主 API 请求时 intercept() 函数拿的 request 对象里有没有 xy-platform-info 这行。

### 3. xy-direction / xy-scene 不是设备常量
之前 inventory 里写"62% 抓包 = '26'、60% = 'fs=1&point=-1'" → 当作设备常量缓存。**错**。jadx 里它们从 libtiny 返回的 native Map 里取出来，是 per-request 动态生成的。命中率高是因为 session 内业务场景相近，不是因为它真常量。纯 Py 路径必须把这两个也算在 libtiny 输出里。

### 4. authorization 从来没在逆向清单里单独列过
它是 /activate 返回的两个 JSON 字段 session / secure_session，缓存即可，不需要任何签名。纯 Py 需要做的就是在 login 流程里把 /activate 响应解包存起来，后续请求直接贴。

### 5. libxyass vs libtiny 归属冲突（**待复核**）
本轮 agent 报告把 shield / x-mini-sig / x-mini-s1 / x-mini-mua / x-mini-gid 全归到 **libxyass**；只有 xy-direction / xy-scene 归 libtiny。

但先前 docs/06_libtiny_analysis.md、docs/31_libtiny_sig_algorithm.md、memory 里 project_libtiny_sig_status 都明确写 x-mini-sig 是 libtiny 产物（还给出了 sig[16:32] 的 SHA-256 公式）。

**冲突**：这里必须静态复核 Native.intercept() 的汇编入口，确认 JNI dispatch 最终落到哪个 .so 的哪个偏移，把 x-mini-sig 的实际生成函数钉死。

**复核步骤**：
1. `strings libxyass.so | grep x-mini-sig` 与 `strings libtiny.so | grep x-mini-sig`，看字符串落哪个库
2. jadx 定位 com.xingin.shield.http.Native 和 libtiny 的 JNI 注册类，分别跟 OnLoad
3. Frida 上一个 hook 打印 intercept() 返回的 Map 全量 keys，确定一个库能不能一次输出这么多头

## 下一步工作顺序（更新后）

1. **复核 libxyass/libtiny 归属冲突**（30 分钟静态）——这决定后续静态 RE 的目标库
2. **复核 shield canonicalize 公式**（主 API vs /patch）——确认 docs/25 的结论在主 API 成立
3. **打通 /activate → authorization 缓存链**（纯 Java，1 小时）——让整个离线签名链少一条依赖
4. 然后再回到 shield inner_hash / byte-mixer 的静态硬啃

## 仍然未变的结论

- `x-mini-mua` 尾的 RSA 签名走 Android KeyStore，TEE 保护，**永远不可能纯 Py**——只能真机预签或缓存
- shield 5 步 pipeline 的 XOR / 拼装 / base64 已纯 Py，唯一缺的是内层 hash 函数
- libtiny x-mini-sig[16:32] 的 SHA-256 公式已纯 Py（前提：归属冲突核对后确实是 libtiny）

## 参考文件

- jadx: `target/jadx_out/sources/`（混淆名，按字符串字面量搜索）
- 抓包: `capture/session1_first_capture_80apis.mitm`, `capture/session2_full_usage_20260411_123810.mitm`
- 先前分类: `docs/01_signature_headers_analysis.md`, `docs/header_algorithms.md`
- 本轮来源：jadx 字符串搜索 + mitm 抓包统计 + 交叉核对
