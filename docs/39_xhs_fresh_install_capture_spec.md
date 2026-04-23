# XHS 删除重装 + 首次启动抓包需求

## 背景

当前 unidbg 黑盒 signer 卡在 `edith.xiaohongshu.com` 的写接口（note CRUD）上——服务器要求 `x-mini-mua` 的 binary tail 包含真机 child 进程收集的 device fingerprint 字节，纯 emulator 无法生成。

已验证：
- `/api/v1/register/android` 校验**极度宽松**（重放 4 天前 body 仍 200）
- `/edith.xiaohongshu.com/api/...` 写接口校验**严格**（任何非真机 mua 都 paradoxical 406）

**需要新情报**：XHS 首次安装启动时（"干净设备"状态）的完整 bootstrap 协议，找服务器承认一个"新设备"的最早时机和校验门槛，以及 install 阶段的 mua 校验是否也宽松。

## 目标

抓一份 **XHS 删除重装 + 首次启动** 的完整流量，覆盖从 app 第一次开屏到 feed 加载完成的全部 HTTP 请求。

## 前置准备

### 1. LSPosed 工作流陷阱（必读）

- xhs uid = **10329**
- Uninstall XHS 会**级联删除** LSPosed 里的 xhs scope——重装后必须**重新添加 scope**
- LSPosed 的 DB 改动需要**完整重启手机**（不能只重启 XHS）
- stub 的 JNI 返回类型必须和原函数一致，否则 crash

### 2. 环境检查

```bash
# 手机 adb 可用
adb devices   # 应该能看到设备

# 代理端口转发
adb forward tcp:18888 tcp:18888

# 确认 LSPosed 管理器正常，xhs-capture 模块已安装
```

### 3. 确认抓包模块

- 模块源代码：`lsposed/xhs-capture/`
- 抓包输出目录：`lsposed/xhs-capture/captures/`（本文档下所有"放到抓包目录"指这里）
- 已有抓包（用于对比）：
  - `xhs_capture_20260413_113326.log`（老 session，无 first-boot）
  - `xhs_crud_20260416_125008.log`（CRUD 场景）

## 抓包操作流程

### Step 1: 卸载 XHS

```bash
adb shell pm uninstall com.xingin.xhs
# 或在手机上长按 XHS icon → 卸载
```

确认卸载干净：
```bash
adb shell pm list packages | grep xingin   # 应该看不到 com.xingin.xhs
```

### Step 2: 清除可能残留的 LSPosed scope 记录

打开 LSPosed Manager → Modules → xhs-capture → Scope 里**确认 xhs 不在列表里**（卸载后应该自动消失，如果还在手动移除一次）。

### Step 3: 重新安装 XHS

优先用**干净的 APK 包**（跟 `target/xhs-*.apk` 同版本最好，确保签名和协议一致）。

```bash
adb install target/xhs-*.apk
# 或从应用商店下载
```

### Step 4: 在 LSPosed 里启用 xhs-capture 对 xhs

打开 LSPosed Manager → Modules → xhs-capture → **Scope → 勾选 XHS**
→ 返回 → **重启手机**（必须！不重启 hook 不 attach）

```bash
adb reboot
# 等手机开机完成
adb devices   # 确认重连
```

### Step 5: 再次确认端口转发（重启后会丢）

```bash
adb forward tcp:18888 tcp:18888
```

### Step 6: 开启抓包

进入抓包模块的 log 目录，开始 tail 以便实时观察（可选）：

```bash
ls -la /sdcard/Android/data/com.xingin.xhs/files/ 2>/dev/null  # 看模块 log 目录
# 或抓包模块指定的输出位置
```

### Step 7: 第一次启动 XHS — 关键抓包窗口

**这一步是核心数据源**。打开 XHS，按这个顺序操作：

1. **0-10 秒**：启动到首屏。不要做任何操作，让 app 自己跑完 bootstrap。
2. **10-30 秒**：会有登录/隐私协议弹窗——都**点同意/允许**（同意隐私协议 = 允许收集设备指纹）。
3. **30-60 秒**：如果弹出登录，**登录一个测试账号**（或跳过登录进入游客模式）。
4. **60-120 秒**：让 feed 加载完，**刷新首页 2-3 次**。
5. **120-180 秒**：点进一个笔记查看（**阅读笔记 = 触发 write endpoint 之一 `/note/imagefeed`**）。
6. **180-240 秒**：返回首页，再次刷新，确保看到**至少 5 个不同 endpoint 的请求**。

**不要点赞/评论/发布笔记**——这些会触发更严格的风控，先保持轻量。

### Step 8: 保存抓包

抓包完成后把 log 文件拉到项目目录：

```bash
# 假设抓包模块输出在手机的某个路径
adb pull /sdcard/Android/data/com.xingin.xhs/files/xhs-capture.log ~/Desktop/test/xhs/lsposed/xhs-capture/captures/xhs_fresh_install_$(date +%Y%m%d_%H%M%S).log
```

或者如果 LSPosed 模块用别的输出机制（比如写到内置 SQLite），请按模块实际方式导出。

**文件命名规范**：`xhs_fresh_install_YYYYMMDD_HHMMSS.log` —— 必须包含 `fresh_install` 关键字以便后续识别。

## 需要的数据质量

### 必须包含

- [ ] 从 **app 启动到首屏加载完** 的所有 HTTP 请求
- [ ] 至少 **5 个不同 endpoint** 的完整 request（method + url + **所有 header** + body）
- [ ] 至少 **3 次 `/api/v1/register/android`** 请求（或等价的 `as.xiaohongshu.com` bootstrap endpoint）
- [ ] 至少 **1 次 edith.xiaohongshu.com 下的 write endpoint**（比如 `/note/imagefeed`、`/user/interact/info`、`/recommend/*`）
- [ ] 每个请求的 **response status + response body**（哪怕 body 不完整至少要有 status）
- [ ] **时间戳**（行级，精确到毫秒）

### 尽量包含

- [ ] app 首次启动时调用的 native JNI 序列（如果 LSPosed 模块支持 trace）
- [ ] `ega.f.b(byte[])` 的入参（如果能 hook） — 这就是 register body.d 的 plaintext 源头
- [ ] `SharedPreferences.putString` 调用（app 会把 kk/tt/device_id 缓存到 sp）

## 重点观察字段（分析时用）

当另一个窗口抓到数据后，交给我分析。以下是我会比对的维度：

### A. 首次启动独有的 endpoint

老抓包没有但首次启动有的 URL，比如：

- `/api/v1/activate_app`
- `/api/v1/install_app`
- `/api/v1/device/register`
- `/api/v1/anon/bootstrap`
- `/edith.xiaohongshu.com/api/.../first_launch`

### B. 首次启动时 mua 内的字段变化

对比：
- 老抓包：`"c":250+`（计数器已高）
- 首次启动：**应该 `"c":1,2,3...`**（从 1 开始）
- `"t"` 子对象：老抓包 `"c":575, "t":30343917`；首次启动可能 `"c":1, "t":0` 或更小
- `"u"` 字段：老抓包 `0000000025071446bbb0c0fca88b03710ab0ac1f`；首次启动可能不同（新 install UUID）

### C. first-boot 阶段的 tail 长度

对比 part[1] raw bytes 长度：
- 老抓包：784B ~ 1152B
- **如果 first-boot 阶段 tail < 400B 且服务器 200** → 说明 install 阶段 mua 宽松，我们纯 unidbg 的 560B tail **有可能被 install 阶段 endpoint 接受**

### D. write endpoint 第一次被调用的时刻

在 log 里找 edith.xiaohongshu.com 下第一个写接口：
- 那个请求的 `"c":N` 值
- 那次 response 是 200 还是 406？

如果 first-boot 阶段 write endpoint 也能 200，那它就是**我们的突破口**。

### E. 服务器下发的 session 字段

response body 里的新字段：
- `kk` / `tt` / `session_token` / `user_token` / `x-mini-*` —— 这些可能是服务器下发给客户端用于后续签名的

## 交付物

抓完后，请把这些放到项目对应位置：

1. **抓包 log**：`lsposed/xhs-capture/captures/xhs_fresh_install_YYYYMMDD_HHMMSS.log`
2. **（如果有）JNI trace**：`lsposed/xhs-capture/captures/xhs_fresh_install_YYYYMMDD_HHMMSS_jni.log`
3. **简短说明**：`scratch/fresh_install_notes.md` — 记录操作时长、登录/游客模式、碰到的异常

## 分析后的预期下一步

拿到数据后我会做：

1. **diff 新老抓包**，列出 first-boot 特有的 endpoint
2. **找 mua 校验等级拐点**（从哪个请求开始服务器变严）
3. **提取服务器首次下发的 session key / token**（如果有）
4. **尝试让我们的 unidbg signer 模拟 first-boot 状态**（低 c、首次 register 前的 mua 等），看能否用这状态打通 write endpoint

如果拿到数据后发现：
- first-boot write endpoint 也宽松 → **纯 unidbg 能打通**
- first-boot 全程严格 → 确认硬天花板，考虑工程化收尾

---

## 补充：如果 LSPosed 抓包有限制

如果 LSPosed 模块不能完整抓到 SSL 流量（很多 app 用 certificate pinning），fallback 方案：

- 用 mitmproxy / charles 作为系统代理 + SSL unpinning（很多 XHS 版本不 pin）
- 或用 justtrustme Xposed 模块禁掉 cert pinning

但优先走 LSPosed 模块路径，因为：
1. 代码已存在 (`lsposed/xhs-capture/`)
2. memory 里已确认 "Frida 在 Pixel 6 / Android 15 上不工作，LSPosed 可以"

---

**任何步骤卡住**可以随时向我反馈，我这边能实时解析新抓包 log。
