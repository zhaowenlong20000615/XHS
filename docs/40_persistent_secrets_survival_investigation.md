# XHS Persistent Secrets 跨 uninstall 存活调查

## 背景与假设

### 核心假设
**XHS 的某些 secrets (包括 `main_hmac`) 在 uninstall + reinstall 之后仍然存活,所以"fresh install"其实没有完全清零客户端身份。**

### 已知证据(需要验证或证伪)

1. **Apr 17 fresh install 抓包** (`lsposed/xhs-capture/captures/xhs_fresh_install_20260417_190044.log`):
   - 冷启动后第一个网络请求(c=1, 07:51:04.410)已经包含稳定的 mua `k` 和 `s` 字段
   - 当时 uninstall+reinstall 流程已走完,但实际 `/data/data/com.xingin.xhs/shared_prefs/s.xml` 里的 `main_hmac` 值此刻已经存在
   - **没有任何服务端下发 main_hmac 的请求窗口**——意味着 main_hmac 不是服务端推送

2. **main_hmac 内部细节**:
   - base64 长度 116 字符,解码 **96 字节** (3×32B)
   - 真机上 `s.xml` 文件 mtime = 首启动时刻
   - 但"文件创建时间"不等于"内容是新生成的"——app 可能从别处读到值再写到新文件

3. **LSPosed 实测**: `xhs-capture` native hook 抓到 libtiny 调 `SharedPreferences.getString("main_hmac", default="")` 返回完整 96B base64——**说明 Java 层此时已经有值存在 SP("s") 里**

### 两种可能性

| 方案 A: Fully local, 每次 fresh install 重生 | 方案 B: 跨 install 存活 |
|---|---|
| 首启动调 SecureRandom 生成 96B,写入 SP("s", "main_hmac") | 从某个 uninstall-safe 位置读出上次的 96B,写入新 install 的 SP |
| 每次 reinstall 值应当**不同** | 每次 reinstall 值应当**相同** |

**验证方法**: `adb shell "su -c 'cat /data/data/com.xingin.xhs/shared_prefs/s.xml'"` 对比两次 fresh install 的 main_hmac 值是否一致。

(4/18 21:00 如果 xhs 已卸载,先看 Apr 17 抓包当时的 main_hmac 是否被继承到今日设备上。)

---

## 任务定义

**在另一个窗口用 LSPosed hook + adb shell,系统性 dump XHS 启动时读的所有 persistent state 源,并确认哪些能跨 uninstall 存活。**

### 预期交付物

1. **`scratch/persistent_survey/fresh_install_dump_v1.txt`**: 第一次 fresh install 启动后所有 SP 文件 + external storage + KeyStore alias
2. **`scratch/persistent_survey/uninstall_leftover.txt`**: uninstall 后 adb 看什么还留着(`/sdcard/...`, `/data/media/0/...`, keystore,  accountmanager)
3. **`scratch/persistent_survey/fresh_install_dump_v2.txt`**: 第二次 fresh install **启动前** 什么还在 + 启动后 vs v1 diff
4. **`scratch/persistent_survey/read_path_trace.log`**: LSPosed hook 抓到的冷启动期间所有 file read / SP read / keystore load
5. **`scratch/persistent_survey/findings.md`**: 结论——哪些 key 跨 install 存活,哪些每次新生

---

## 实验流程

### Phase 0 — 前置环境检查

```bash
adb devices                 # 设备连着
adb root 2>/dev/null || true
adb shell su -c "id"        # root 可用 (需要读 /data/data/)
```

LSPosed manager 确认 `xhs-capture` 模块已启用 (参考 [../lsposed/xhs-capture/](../lsposed/xhs-capture/))。

### Phase 1 — 当前 install state 基线 dump

**目标**: 把**当前 XHS 装好跑过的状态**完整 dump,作为"install v1"快照。

#### 1a. SharedPreferences 全 dump

```bash
mkdir -p scratch/persistent_survey
# dump 整个 shared_prefs 目录 (不要 cat 单文件,要全部)
adb shell "su -c 'ls /data/data/com.xingin.xhs/shared_prefs/ | wc -l'"
adb shell "su -c 'tar czf /data/local/tmp/xhs_sp_v1.tar.gz -C /data/data/com.xingin.xhs shared_prefs/'"
adb pull /data/local/tmp/xhs_sp_v1.tar.gz scratch/persistent_survey/
# 解压,逐文件 sha256 + 内容 snapshot
cd scratch/persistent_survey && tar xzf xhs_sp_v1.tar.gz && cd -
```

**特别关注**(先单独 cat 这几个):
```bash
for f in s.xml Xhs.xml StatusBarDefaultConfigSharePreference.xml BuglySdkInfos.xml \
         cn.jpush.preferences.v2.xml LocationSDK.xml; do
    echo "=== $f ==="
    adb shell "su -c 'cat /data/data/com.xingin.xhs/shared_prefs/$f'" 2>&1
done > scratch/persistent_survey/sp_key_files_v1.txt
```

#### 1b. 内部存储其他可能藏 secret 的目录

```bash
adb shell "su -c 'ls -la /data/data/com.xingin.xhs/'" > scratch/persistent_survey/data_root_v1.txt
adb shell "su -c 'ls -lR /data/data/com.xingin.xhs/files/ 2>/dev/null | head -200'" > scratch/persistent_survey/files_v1.txt
adb shell "su -c 'ls -lR /data/data/com.xingin.xhs/databases/ 2>/dev/null'" > scratch/persistent_survey/databases_v1.txt
adb shell "su -c 'ls -lR /data/data/com.xingin.xhs/cache/ 2>/dev/null | head -50'" > scratch/persistent_survey/cache_v1.txt
# no_backup 很关键 (Google 推荐存敏感数据的地方)
adb shell "su -c 'ls -lR /data/data/com.xingin.xhs/no_backup/ 2>/dev/null'" > scratch/persistent_survey/no_backup_v1.txt
# app 特有 code_cache
adb shell "su -c 'ls -lR /data/data/com.xingin.xhs/code_cache/ 2>/dev/null | head -50'" > scratch/persistent_survey/code_cache_v1.txt
```

#### 1c. 外部存储 (uninstall 通常不清除!)

```bash
# Android 11+ scoped storage: /sdcard/Android/data 和 /sdcard/Android/media 在 uninstall 时行为不同
adb shell "ls -lR /sdcard/Android/data/com.xingin.xhs/ 2>/dev/null" > scratch/persistent_survey/sdcard_data_v1.txt
adb shell "ls -lR /sdcard/Android/media/com.xingin.xhs/ 2>/dev/null" > scratch/persistent_survey/sdcard_media_v1.txt
# 任何公共目录以 xhs/xiaohongshu/xingin 开头的文件夹
adb shell "find /sdcard -maxdepth 3 -iname '*xhs*' -o -iname '*xiaohongshu*' -o -iname '*xingin*' 2>/dev/null | head -50" > scratch/persistent_survey/sdcard_scan_v1.txt
# /sdcard/redplanet, /sdcard/.redplanet 之类 XHS 特有路径
adb shell "ls -la /sdcard/redplanet /sdcard/.redplanet /sdcard/Pictures/redplanet 2>/dev/null" >> scratch/persistent_survey/sdcard_scan_v1.txt
```

#### 1d. Android 系统持久存储 (uninstall 不碰!)

```bash
# AndroidKeyStore: 任何以 com.xingin.xhs 相关 alias 的 key
adb shell "su -c 'cmd keystore2 list_entries 2>/dev/null'" | grep -i xhs > scratch/persistent_survey/keystore_v1.txt 2>&1
# AccountManager
adb shell "dumpsys account" | grep -B2 -A5 "xingin\|xhs" > scratch/persistent_survey/accounts_v1.txt 2>&1
# 设备 id (XHS 可能读 Settings.Secure.ANDROID_ID —— 这个肯定跨 install)
adb shell "settings get secure android_id" > scratch/persistent_survey/android_id.txt
# InstallReferrer (Google Play 安装时来源)
adb shell "dumpsys package com.xingin.xhs | grep -i 'firstInstallTime\|lastUpdateTime\|installerPackage'" > scratch/persistent_survey/install_meta_v1.txt
```

#### 1e. 当前 main_hmac 值(对照用)

```bash
adb shell "su -c 'cat /data/data/com.xingin.xhs/shared_prefs/s.xml'" > scratch/persistent_survey/main_hmac_v1.txt
```

### Phase 2 — Uninstall

```bash
adb shell pm uninstall com.xingin.xhs
```

**立即** (不要重启手机,以免扰动磁盘状态) dump leftover:

```bash
# /data/data/com.xingin.xhs/ 目录应该消失
adb shell "su -c 'ls -la /data/data/com.xingin.xhs/' 2>&1" > scratch/persistent_survey/data_after_uninstall.txt
# 但 /sdcard 不会清
adb shell "ls -lR /sdcard/Android/data/com.xingin.xhs/ 2>/dev/null" > scratch/persistent_survey/sdcard_data_after_uninstall.txt
adb shell "ls -lR /sdcard/Android/media/com.xingin.xhs/ 2>/dev/null" > scratch/persistent_survey/sdcard_media_after_uninstall.txt
adb shell "find /sdcard -maxdepth 3 -iname '*xhs*' -o -iname '*xiaohongshu*' -o -iname '*xingin*' 2>/dev/null" > scratch/persistent_survey/sdcard_scan_after_uninstall.txt
# keystore / accounts
adb shell "su -c 'cmd keystore2 list_entries 2>/dev/null | grep -i xhs'" > scratch/persistent_survey/keystore_after_uninstall.txt 2>&1
adb shell "dumpsys account" | grep -B2 -A5 "xingin\|xhs" > scratch/persistent_survey/accounts_after_uninstall.txt 2>&1
```

**中期判断点**: 看 `sdcard_*_after_uninstall.txt` 是否还有文件。如果有,就重点检查它们的内容,特别是小文件(大概率是 secret),大文件(大概率是 cache)。

### Phase 3 — Reinstall (先不启动)

```bash
adb install target/xhs.apk     # 或当前使用的 APK 路径
# 不要启动!先查磁盘
adb shell "su -c 'ls -la /data/data/com.xingin.xhs/'" > scratch/persistent_survey/data_after_install_before_launch.txt
adb shell "su -c 'ls -la /data/data/com.xingin.xhs/shared_prefs/ 2>/dev/null'" > scratch/persistent_survey/sp_after_install_before_launch.txt
# shared_prefs 此时应该是空的或不存在
```

### Phase 4 — LSPosed hook 启动并捕获冷启动读磁盘轨迹

**关键**: 这里要 hook 所有"读取 persistent state"的路径,记录每一次读。

#### 4a. 扩展 xhs-capture 模块(或写新模块 `xhs-read-tracer`)

要 hook 的类/方法 (Xposed 语法):

```java
// 1. SharedPreferences 读
XposedHelpers.findAndHookMethod("android.content.SharedPreferences$Editor", /* ... */);
XposedHelpers.findAndHookMethod("android.app.SharedPreferencesImpl", loader, "getString",
        String.class, String.class, new XC_MethodHook() {
    @Override protected void afterHookedMethod(MethodHookParam param) {
        String fileName = (String) XposedHelpers.getObjectField(param.thisObject, "mFile");
        String key = (String) param.args[0];
        String def = (String) param.args[1];
        Object ret = param.getResult();
        log("SP.getString file=" + fileName + " key=" + key + " def=" + def +
            " ret=" + (ret == null ? "<null>" : ret.toString().substring(0, Math.min(60, ret.toString().length()))));
    }
});
// 也 hook putString / getInt / putInt / getBoolean ...

// 2. File I/O (任何外部文件读)
XposedHelpers.findAndHookConstructor("java.io.FileInputStream", loader, String.class,
        new XC_MethodHook() { /* log path */ });
XposedHelpers.findAndHookConstructor("java.io.FileInputStream", loader, File.class, /* ... */);

// 3. KeyStore
XposedHelpers.findAndHookMethod("java.security.KeyStore", loader, "load",
        InputStream.class, char[].class, /* log alias enumeration */);

// 4. AccountManager
XposedHelpers.findAndHookMethod("android.accounts.AccountManager", loader, "getAccountsByType",
        String.class, /* log account types queried */);

// 5. Settings.Secure.getString
XposedHelpers.findAndHookMethod("android.provider.Settings$Secure", loader, "getString",
        ContentResolver.class, String.class, /* log which settings read */);
```

每个 hook 输出格式化的 log 行: `<timestamp> <category> <detail>` 到 `/sdcard/xhs_read_trace.log`。

#### 4b. 启动并抓

```bash
# LSPosed scope 勾选新模块
adb reboot      # LSPosed 需要重启生效
# ... 等手机开机 ...
adb shell monkey -p com.xingin.xhs -c android.intent.category.LAUNCHER 1
# 等 2 分钟让 app bootstrap 完
sleep 120
# pull log
adb pull /sdcard/xhs_read_trace.log scratch/persistent_survey/read_path_trace.log
# 同时再 dump 一次 state
adb shell "su -c 'cat /data/data/com.xingin.xhs/shared_prefs/s.xml'" > scratch/persistent_survey/main_hmac_v2.txt
```

### Phase 5 — 对比分析

```bash
# 最关键的对比: v1 main_hmac vs v2 main_hmac
diff scratch/persistent_survey/main_hmac_v1.txt scratch/persistent_survey/main_hmac_v2.txt
```

**如果相同** → main_hmac 跨 install 存活 → 值必然来自磁盘某处。去 `read_path_trace.log` 里找冷启动时 app 读了哪些文件/SP/keystore,那就是 leak 源。

**如果不同** → main_hmac 每次 fresh install 重生 → 调查集中在 bootstrap 流程里的 `SecureRandom` 调用。

#### 5a. 从 trace log 里抽出可疑读

```bash
# 冷启动前 5 秒内的所有读
head -n 500 scratch/persistent_survey/read_path_trace.log | grep -iE "SP.getString|FileInputStream|KeyStore|Settings.Secure" > \
    scratch/persistent_survey/early_boot_reads.txt
# 读了什么没有 put → 跨 install 继承的候选
# 可以用 awk 做 get vs put 差集
awk '/SP.getString/ {k=$0; sub(/.*key=/, "", k); sub(/ def=.*/, "", k); print "GET " k}
     /SP.putString/ {k=$0; sub(/.*key=/, "", k); sub(/ val=.*/, "", k); print "PUT " k}' \
     scratch/persistent_survey/read_path_trace.log | \
    sort -u | awk '/^GET / {g[$2]=1} /^PUT / {p[$2]=1} END {for (k in g) if (!p[k]) print k}' \
    > scratch/persistent_survey/read_but_never_wrote.txt
```

`read_but_never_wrote.txt` 里的 key 就是**跨 install 继承**的嫌疑(reading without having written ever = must have existed before this session)。

---

## 可能的 persistent 存储位置清单(需要逐一排查)

| 位置 | uninstall 清除? | 检查方法 |
|---|---|---|
| `/data/data/com.xingin.xhs/shared_prefs/*.xml` | ✅ 清 | Phase 1a |
| `/data/data/com.xingin.xhs/files/` | ✅ 清 | Phase 1b |
| `/data/data/com.xingin.xhs/databases/` | ✅ 清 | Phase 1b |
| `/data/data/com.xingin.xhs/no_backup/` | ✅ 清 | Phase 1b |
| `/sdcard/Android/data/com.xingin.xhs/` | ⚠️ Android 11+ 应清,实际可能不清 | Phase 1c, 2 |
| `/sdcard/Android/media/com.xingin.xhs/` | ❌ **不清** | Phase 1c, 2 |
| `/sdcard/redplanet/`, `/sdcard/xhs/` 等 | ❌ 不清 | Phase 1c, 2 |
| `Settings.Secure.ANDROID_ID` | ❌ 不清(factory reset 才换) | hook Settings 读 |
| `AndroidKeyStore` alias | ❌ **有时不清**(APK 签名关联) | hook KeyStore.load |
| `AccountManager` 存的 account | ❌ 不清(系统级) | dumpsys account |
| 其他 app ContentProvider 存的 | ❌ 不清 | hook ContentResolver |
| `Build.getSerial()` / `TelephonyManager` imei | ❌ 不清 | hook 相关 API |

**最可疑 top 3**:
1. `AndroidKeyStore` — XHS 可能存 HMAC key 在这,uninstall 不清(Android 行为)
2. `/sdcard/Android/media/com.xingin.xhs/` — media 目录在任何 Android 版本 uninstall 都不清
3. `Settings.Secure.ANDROID_ID` — 已知 fresh install 都会拿到同一个 android_id (ce2a0131-c4e3-483e-aeb9-681b1d16f9ba),XHS 用它当 seed

---

## 已知上下文

- **设备**: Pixel 6 + Android 15
- **XHS 版本**: 9.19.0 (build 9190807)
- **包名**: `com.xingin.xhs`
- **root**: 有 (设备已 Magisk)
- **LSPosed**: 已装,xhs-capture 模块已启用 (`lsposed/xhs-capture/`)
- **已知的 deviceId**: `aa293284-0e77-319d-9710-5b6b0a03bd9c` (是 DRM fallback 的 widevine id)
- **已知 android_id**: `a5b8432c4477b553` (8 字节十六进制)
- **当前 main_hmac 值** (要对比):
  ```
  9sQx+OUeOG4/W1OtYjlyPRNG6jZZ4XAzcXCOhET6/dgs1/LMxX51kAILRvtnjXeqK2rzDQwChJOBNBosBirHV5sha5DKMl7W05PDRcsC88LLvMr9/92wemrjCb2ykOeB
  ```

---

## 简化快速验证路径(如果时间紧)

**不用做全 hook**,就做**两次 fresh install** 对比:

```bash
# Run 1
adb uninstall com.xingin.xhs
adb install target/xhs.apk
adb shell monkey -p com.xingin.xhs 1
sleep 60
adb shell "su -c 'cat /data/data/com.xingin.xhs/shared_prefs/s.xml'" > run1.txt

# Run 2 — 等几分钟确保 background service 也清完了
adb shell am force-stop com.xingin.xhs
adb uninstall com.xingin.xhs
sleep 5
adb install target/xhs.apk
adb shell monkey -p com.xingin.xhs 1
sleep 60
adb shell "su -c 'cat /data/data/com.xingin.xhs/shared_prefs/s.xml'" > run2.txt

diff run1.txt run2.txt
```

- **相同** → main_hmac 跨 install 存活 ✓ (用户假设正确)
- **不同** → main_hmac 每次新生 (用户假设错误,main_hmac 真是 local RNG)

**如果相同**,再做:
```bash
# 手动 rm 可能泄漏的位置,再 install
adb shell "su -c 'rm -rf /sdcard/Android/media/com.xingin.xhs'"
adb shell "su -c 'rm -rf /sdcard/Android/data/com.xingin.xhs'"
adb shell "rm -rf /sdcard/redplanet /sdcard/xhs"
# KeyStore 里 XHS 相关 alias 删掉(如果找到)
adb shell "su -c 'keystore2 delete_entry xxx'"
adb install target/xhs.apk
adb shell monkey -p com.xingin.xhs 1
sleep 60
adb shell "su -c 'cat /data/data/com.xingin.xhs/shared_prefs/s.xml'" > run3.txt
diff run1.txt run3.txt
```

如果 run3 和 run1/run2 不同 → **找到了泄漏源**(就是刚 rm 的某个东西)。

---

## 对主项目的意义

1. 如果 main_hmac 跨 install 存活 → 我们的 unidbg 签名策略可以**硬编码**这个值(因为真机每次都用同一个)。**已经这么做了** (`XhsCombinedSigner.MAIN_HMAC_VALUE`)——这是对的。

2. 如果每次 fresh install main_hmac 不同 → app 必须先**本地 bootstrap** 生成一次,unidbg 需要模拟这个 bootstrap 路径。我们的 signer 可能要加一个"生成 main_hmac"的 initialize 阶段。

3. 如果泄漏源是 `AndroidKeyStore` → 可能还泄漏了**其他 key**(AES key? RSA key?),我们需要完整列举。这些 key 可能就是 `k`, `s`, xy-platform-info 里某些固定字段的源。

4. 如果泄漏源是 `Settings.Secure.ANDROID_ID` 之类 → 真实 client 的"身份"其实就是 `device_id + android_id + 某种 HMAC-of-HMAC` 的复合,我们 unidbg 已经有所有这些值,那 main_hmac 值就是**可以从已知数据派生出来的**——派生算法就是突破点。

---

## 任何步骤卡住请反馈

这份调查的数据一旦拿到,主项目可以直接判断:
- 是否可以**跨 install 复用** main_hmac(最简方案)
- 还是必须**实现 main_hmac 生成**(unidbg 要补 bootstrap 逻辑)
- 还是 server 根本不在乎 main_hmac 的值(只要 mua 格式对,HMAC 自洽即可)
