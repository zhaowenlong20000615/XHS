# 需求 (Amendment): fresh-install 严谨条件下重抓 d7.a + mua 首条

**受众**: 负责 LSPosed xhs-capture 的窗口
**修订**: docs/51 + docs/53 + docs/54 的 trace 都在 "xhs 已经跑过 N 次" 的非纯净状态下抓的,导致 "t 字段存在" 等假设无法区分"来自 init"还是"来自 disk cache"。本文档指定**严格 fresh 条件**。
**前置验证**: docs/51 的 mua 首条 `"c":2` 而不是 `c:1` 暴露了残留状态 — 本次必须 `c==1`。

---

## 1. 为什么重抓 (背景)

之前的 trace 存在以下残留污染:

| 残留源 | 影响 |
|---|---|
| `/data/data/com.xingin.xhs/shared_prefs/*.xml` | main_hmac / session counter 预热 |
| `/data/data/com.xingin.xhs/databases/*.db` | tracker event 持久化 |
| `/data/data/com.xingin.xhs/files/.tistore` | libtiny 自己 accumulator 快照 |
| `/sdcard/Download/ks.sr0` (4028 B) | **跨 uninstall 残留** xhs device fingerprint |
| `/sdcard/Android/data/com.xingin.xhs/*` | app sdcard 缓存 |
| server 下发 (active session token / remote config) | `xy-ter-str` 推送 main_hmac |

我们拿着 "非 fresh" 的数据推断 "t 字段是 init-generated",如果真相其实是 "t 字段 = disk cache deserialize",那 unidbg 走弯路半天都白做。

**本次目标**: 用严格 fresh 条件抓 trace,确定 t 字段的**真实来源**,三选一:
- 来源 A: libtiny C++ ctor 初始化 (unidbg 应能复现)
- 来源 B: disk cache deserialize (unidbg 纯黑盒复现不了,是上限)
- 来源 C: 首次网络交互后 server push (可通过 fake proxy 复现)

---

## 2. 严格 fresh 流程

### 前置: 项目中几个绝对路径

```
PROJ=/Users/zhao/Desktop/test/xhs
APK=$PROJ/target/xhs.apk                                 # 9.19.0 APK, 161MB
CAP=$PROJ/lsposed/xhs-capture/captures                   # 输出目录
LSPOSED_DB=/data/adb/lspd/config/modules_config.db       # 手机上 LSPosed 数据库
```

下面所有脚本的 `$PROJ` / `$APK` / `$CAP` 按这套解析。

### 2.1 清理脚本 (必须全跑, 所有路径用绝对值)

```bash
#!/bin/bash
set -e
PROJ=/Users/zhao/Desktop/test/xhs
APK=$PROJ/target/xhs.apk
PKG=com.xingin.xhs

# 0. 确认 APK 存在 + 可读
[ -f "$APK" ] || { echo "APK not found at $APK"; exit 1; }

# 1. uninstall (清 /data/data/$PKG + dex cache, 但会 cascade-delete LSPosed scope)
adb uninstall $PKG || echo "already gone"

# 2. 清 sdcard 残留 (uninstall 不会动 sdcard)
adb shell "su -c 'rm -rf /sdcard/Android/data/$PKG'"
adb shell "su -c 'rm -rf /sdcard/Android/obb/$PKG'"
adb shell "su -c 'rm -f /sdcard/Download/ks.sr0 /sdcard/Download/ks.sr0.tmp'"
# tistore 清干净 (注意 -delete 不是只 list)
adb shell "su -c 'find /sdcard -name \".tistore*\" -delete 2>/dev/null || true'"
adb shell "su -c 'find /sdcard -iname \"*xingin*\" -type f -delete 2>/dev/null || true'"
# 确认 sdcard 干净
echo "--- sdcard xhs 残留 (应为空) ---"
adb shell "su -c 'find /sdcard -iname \"*xingin*\" 2>/dev/null; find /sdcard -name \"ks.sr0*\" 2>/dev/null'"

# 3. 清 logcat 缓存
adb shell logcat -c

# 4. 装 APK
adb install -r "$APK"

# 5. 关键: LSPosed scope 在 uninstall 时被 cascade-delete 了, 必须手动重插
#    (见 memory reference_lsposed_module_workflow §3 — "Uninstall cascade-deletes scope rows")
#    pull DB 到 Mac → sqlite 重新 INSERT → push 回去 → reboot
TMP=$(mktemp -d)
adb pull $LSPOSED_DB $TMP/modules_config.db
# 同时 pull WAL/SHM 避免 stale read (memory §4)
adb pull /data/adb/lspd/config/modules_config.db-wal $TMP/ 2>/dev/null || true
adb pull /data/adb/lspd/config/modules_config.db-shm $TMP/ 2>/dev/null || true

sqlite3 $TMP/modules_config.db <<SQL
-- 查 xhs-capture module mid
SELECT mid FROM modules WHERE module_pkg_name='com.xhs.capture';
-- INSERT scope (若 uninstall 清掉的话)
INSERT OR IGNORE INTO scope(mid, app_pkg_name, user_id)
SELECT mid, 'com.xingin.xhs', 0 FROM modules WHERE module_pkg_name='com.xhs.capture';
-- reinstall 后 apk_path 可能变, 更新 (memory §2)
UPDATE modules SET apk_path=(
  SELECT path FROM (SELECT '/data/app/... 实际路径请 adb shell pm path com.xingin.xhs 确认' AS path)
) WHERE 1=0;  -- 这条先注释, 实际用下面 shell
PRAGMA wal_checkpoint(TRUNCATE);
SQL

# 重新查 + 更新 xhs apk_path (APK 每次 install 目录 hash 会变)
XHS_APK_PATH=$(adb shell "pm path $PKG" | sed 's/package://' | tr -d '\r')
echo "--- xhs apk_path (用于 LSPosed scope) ---"
echo "$XHS_APK_PATH"
# 实际 modules_config.db 里 modules.apk_path 是 xhs-capture 自己的 APK, 不是 xhs 的, 这步一般不用改
# 但若 xhs-capture 也被 uninstall 过, 要更新 modules 表

# push 回
adb shell "su -c 'rm -f /data/adb/lspd/config/modules_config.db-wal /data/adb/lspd/config/modules_config.db-shm'"
adb push $TMP/modules_config.db $LSPOSED_DB
adb shell "su -c 'chown system:system $LSPOSED_DB && chmod 644 $LSPOSED_DB'"
rm -rf $TMP

# 6. 断网 — iptables + 飞行模式双保险
adb shell "su -c 'settings put global airplane_mode_on 1'"
adb shell "su -c 'am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true'"
# iptables 用 xhs UID, 防止 push channel 长连接
XHS_UID=$(adb shell "dumpsys package $PKG | grep userId= | head -1" | sed 's/.*userId=//' | tr -d '\r')
echo "xhs UID = $XHS_UID"
adb shell "su -c 'iptables -F OUTPUT'" || true
adb shell "su -c 'iptables -A OUTPUT -m owner --uid-owner $XHS_UID -j REJECT'"

# 7. 确认干净
echo "--- /data/data/$PKG/ (应只有 lib/code_cache) ---"
adb shell "su -c 'ls -la /data/data/$PKG/ 2>/dev/null'"
```

### 2.2 抓取脚本

```bash
PROJ=/Users/zhao/Desktop/test/xhs
CAP=$PROJ/lsposed/xhs-capture/captures
PKG=com.xingin.xhs

# 8. reboot double (LSPosed dex cache 坑, 见 docs/43)
adb reboot && adb wait-for-device
adb shell 'while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 2; done'
adb reboot && adb wait-for-device
adb shell 'while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 2; done'

# 9. reboot 把 airplane mode 重置了, 重新断网
adb shell "su -c 'settings put global airplane_mode_on 1'"
adb shell "su -c 'am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true'"
XHS_UID=$(adb shell "dumpsys package $PKG | grep userId= | head -1" | sed 's/.*userId=//' | tr -d '\r')
adb shell "su -c 'iptables -A OUTPUT -m owner --uid-owner $XHS_UID -j REJECT'"

# 10. cold start + monkey
adb shell input keyevent 82  # unlock
adb shell "am force-stop $PKG"
adb shell "su -c 'rm -f /data/data/$PKG/files/tiny_cmds.jsonl /data/data/$PKG/files/d7_table.jsonl'"
adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1"

# 11. 绝对不要登录 / 允许权限弹窗
# 45s 够首屏 init 完 (断网所以 app 可能卡 loading, 无所谓, 只要 libtiny init 跑到就行)
sleep 45

# 12. pull (绝对路径)
TS=$(date +%s)
adb shell "su -c 'cp /data/data/$PKG/files/tiny_cmds.jsonl /sdcard/tiny_cmds_fresh1_$TS.jsonl && chmod 666 /sdcard/tiny_cmds_fresh1_$TS.jsonl'"
adb shell "su -c 'cp /data/data/$PKG/files/d7_table.jsonl /sdcard/d7_table_fresh1_$TS.jsonl && chmod 666 /sdcard/d7_table_fresh1_$TS.jsonl'"
# xhs-capture 自己的 main log (含 mua 抓取) 也要 pull
adb shell "su -c 'cp /data/data/$PKG/files/xhs_capture.log /sdcard/xhs_fresh1_$TS.log && chmod 666 /sdcard/xhs_fresh1_$TS.log'" || true
adb pull /sdcard/tiny_cmds_fresh1_$TS.jsonl $CAP/
adb pull /sdcard/d7_table_fresh1_$TS.jsonl $CAP/
adb pull /sdcard/xhs_fresh1_$TS.log $CAP/ || true

# 13. 立即自检: 首条 mua 的 c 值
python3 <<PY
import base64, json, re, sys
try:
    log = open('$CAP/xhs_fresh1_$TS.log').read()
except FileNotFoundError:
    print('WARN: xhs_capture.log not found, skip c-check'); sys.exit(0)
for m in re.finditer(r'x-mini-mua:\s*([A-Za-z0-9_\-]+)', log):
    mua = m.group(1)
    jb = mua.split('.')[0]
    pad = '=' * ((4 - len(jb) % 4) % 4)
    js = json.loads(base64.urlsafe_b64decode(jb + pad))
    print(f'FIRST mua: c={js.get("c")} has_t={"t" in js} keys={sorted(js.keys())}')
    if js.get('c') != 1:
        print('❌ c != 1 → 有残留!stop 不要二次抓, 先调清理脚本')
        sys.exit(2)
    print('✅ c==1, 可以进 2.3 二次抓')
    break
PY
```

### 2.2.1 hook 挂上验证 (关键, cold start 后立即跑)

LSPosed scope 有时重启后没正确加载,导致 hook **根本没装**,jsonl 文件空/不存在。必须先验证:

```bash
# xhs-capture 自己会打 "attached to com.xingin.xhs" 这条 log
adb shell "su -c 'grep -q \"attached to com.xingin.xhs\" /data/data/com.xingin.xhs/files/xhs_capture.log && echo HOOK_OK || echo HOOK_MISSING'"

# jsonl 应该 > 0 行
adb shell "su -c 'wc -l /data/data/com.xingin.xhs/files/tiny_cmds.jsonl /data/data/com.xingin.xhs/files/d7_table.jsonl 2>/dev/null'"
```

**如果输出 `HOOK_MISSING` 或 jsonl 0 行**:
- LSPosed scope 没恢复成功
- 回 2.1 step 5 重新 pull+edit+push DB,再 reboot
- 别进 2.3 ,这轮数据废

### 2.3 二次重抓 (必须)

**第一次 c == 1 才跑第二次**。否则调 2.1 清理脚本。

重复 2.1 全部步骤 (再 uninstall + 清 sdcard + DB re-insert scope + reboot × 2 + install) 再跑 2.2 (把所有 `fresh1` 换成 `fresh2`),产出:
- `/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/tiny_cmds_fresh2_<ts>.jsonl`
- `/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/d7_table_fresh2_<ts>.jsonl`
- `/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/xhs_fresh2_<ts>.log`

**为什么两次**: 如果两次 cmd 序列 + long_arg + byte dump 完全一致,说明无外部 state 依赖 (纯 ctor)。不一致的部分就是**依赖 disk / 网络 / 时间**的部分。

---

## 3. 交付验收 (另一窗口自测必过)

### 3.1 每份文件基本检查

```bash
for F in tiny_cmds_fresh1_*.jsonl tiny_cmds_fresh2_*.jsonl; do
    cd lsposed/xhs-capture/captures
    echo "=== $F ==="
    wc -l $F
    head -1 $F | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(f'first seq={d[\"seq\"]} cmd={d.get(\"cmd\")}')"
    # 第一个 -1750991364 (sign) 的 mua c 值必须是 1 不是 2
    # 这条需要在单独的 mua log 里看, 不在 tiny_cmds.jsonl 里 (但可以用 LSPosed capture main log 提取)
done
```

### 3.2 mua 首条 c == 1 验证 (关键!)

从 xhs-capture 主 log 提取冷启后 **第一条** `x-mini-mua`:

```bash
python3 << 'EOF'
import base64, json, re
log_path = '/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/xhs_fresh_install_<new_ts>.log'
with open(log_path) as f:
    for line in f:
        m = re.search(r'x-mini-mua:\s*([A-Za-z0-9_\-]+)', line)
        if m:
            mua = m.group(1)
            json_b64 = mua.split('.')[0]
            pad = '=' * ((4 - len(json_b64) % 4) % 4)
            js = json.loads(base64.urlsafe_b64decode(json_b64 + pad))
            print(f'first mua: c={js.get("c")} has_t={("t" in js)}')
            print(f'  full json: {json.dumps(js, ensure_ascii=False)}')
            break
EOF
```

**必须**:
- [ ] `c == 1` (如果 c > 1 说明仍有残留, 退回重清)
- [ ] 报告 `has_t` 是 True 还是 False
- [ ] 报告完整 JSON 的 keys 集合

### 3.3 两次 diff

```bash
# cmd 序列对比
python3 << 'EOF'
import json
def summary(path):
    cmds = []
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            cmds.append((d['cmd'], d.get('arg_count', -1)))
    return cmds

a = summary('/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/tiny_cmds_fresh1_<ts>.jsonl')
b = summary('/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/tiny_cmds_fresh2_<ts>.jsonl')
print(f'run1: {len(a)} calls, {len(set(x[0] for x in a))} unique cmds')
print(f'run2: {len(b)} calls, {len(set(x[0] for x in b))} unique cmds')
# diff first 30 entries (cmd only)
for i, (x, y) in enumerate(zip(a[:30], b[:30])):
    marker = '==' if x == y else '!='
    print(f'  [{i:3d}] {x} {marker} {y}')
EOF
```

**必须**:
- [ ] 两次 unique cmd 集合一致 (或偏差 ≤ 2)
- [ ] 前 30 条 cmd 序列一致 (允许顺序小波动)
- [ ] 报告差异: 哪些 cmd 只在一次出现, 哪些 cmd 调用次数差 > 3

### 3.4 d7.a long_arg 对比

```bash
python3 << 'EOF'
import json
def longs(path):
    xs = []
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            if d.get('cmd') == 1140071423 and 'long_arg' in d:
                xs.append(d['long_arg'])
    return xs

a = longs('.../d7_table_fresh1_<ts>.jsonl')
b = longs('.../d7_table_fresh2_<ts>.jsonl')
print(f'run1 d7.a long_args: unique={len(set(a))}, first 5={a[:5]}')
print(f'run2 d7.a long_args: unique={len(set(b))}, first 5={b[:5]}')
EOF
```

**必须报告**:
- [ ] 两次 long_arg 是否**完全不同** (运行时生成确认) 或**都是同值** (disk 持久化)
- [ ] 若 run1 里所有 long_arg 都相同且 run2 里也都相同,但两次的值不同 → long_arg = "进程 startup 时生成一次的 session handle",每次启动不同
- [ ] 若同值 → long_arg = persistent handle,从 disk 读的

### 3.5 网络确认

```bash
# 确认断网成功
adb shell "su -c 'dumpsys network_management' | grep -i 'active\|airplane'" | head -3
adb shell "su -c 'iptables -L OUTPUT -n'" | head  # 如果用 iptables 拦
```

**必须**:
- [ ] 抓取期间 app 确实未发出过出站 HTTPS (logcat 或 tcpdump 验证)
- [ ] 若有零散请求 (push 长连接尝试 / DNS) 算正常, 但不应有 edith.xiaohongshu.com 成功请求

---

## 3.6 交付 artifact 清单 (必须 6 个文件齐)

最终要发我的文件 (绝对路径):
```
/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/tiny_cmds_fresh1_<ts>.jsonl
/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/d7_table_fresh1_<ts>.jsonl
/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/xhs_fresh1_<ts>.log
/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/tiny_cmds_fresh2_<ts>.jsonl
/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/d7_table_fresh2_<ts>.jsonl
/Users/zhao/Desktop/test/xhs/lsposed/xhs-capture/captures/xhs_fresh2_<ts>.log
```

加 1 份交付 summary `docs/56_fresh_trace_delivery.md`,格式参照 docs/51/54。

**不齐则退回**,别发给我半成品。

---

## 4. 交付简报必写

1. 两次 cold-start 的时间戳
2. 清理脚本执行完的 `/data/data/com.xingin.xhs/` 目录 dump (证明干净)
3. mua 首条 c 值 + 是否有 t 字段 (两次都写)
4. cmd 总数 / unique cmd 数 (两次)
5. d7.a long_arg 分布 (两次)
6. 是否有未预期的网络请求

---

## 5. 我拿到数据后的决策树

### 5.1 "t" 字段是否在 fresh install 的首条 mua 里?

- **有** → tracker **由 libtiny ctor 初始化**,不依赖 disk。我们 unidbg 侧继续深追 C++ ctor 执行路径。方向不变但更聚焦。
- **无** → tracker **来自 disk cache deserialize**,fresh install 首条 mua 也没有。**我们 unidbg 现在的 1165B 就是 fresh install 上限**,**2/5 就是 fresh install 的天花板**。完全停手 tracker 方向,直接接受 2/5 去打磨其他东西。

### 5.2 两次 long_arg 完全不同还是相同?

- **不同** → 每次进程 startup 生成,是某个 Java object 的 hashCode / identityHashCode
- **相同** → 从 disk 读 (user_id / device_id 的 hash)

### 5.3 fresh install 的 cmd 总数大约?

- 和 docs/51 的 617 一样多 → 残留数据影响小, 主流程稳定
- 明显少 (< 300) → 残留数据导致真机启动时做了很多 "历史 state sync" 动作, fresh 轻得多

---

## 6. 一句话总结

**用完全纯净的 xhs (uninstall + sdcard 清 + 断网 + 新装) 冷启动 2 次,比对 tiny_cmds.jsonl / d7_table.jsonl 的 first mua c 值 / t 字段存在性 / long_arg 分布。这能一次性确认 tracker 到底是 init-generated / disk-cached / server-pushed 哪一种,我后面的 unidbg 黑盒路线就彻底分叉到正路。**

如果脚本跑到一半某一步不行 (比如 adb install 找不到 APK, 或 iptables 拒不生效),**不要**绕过 — 发状态给我,我帮调整 spec。别用"差不多"的 state 抓了浪费一轮。
