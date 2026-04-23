# 需求: LSPosed hook libtiny d7.a 内部 Long→指针表

**受众**: 负责 LSPosed xhs-capture 扩展的窗口
**工具**: LSPosed (复用现有 `lsposed/xhs-capture` infrastructure,**不用 Frida** — 项目 memory 确认 Frida 在 Pixel 6 / Android 15 死路)
**产出**: `lsposed/xhs-capture/captures/d7_table_<ts>.jsonl` + 简报
**目的**: 解决 unidbg 调 d7.a 时 `UC_ERR_FETCH_UNMAPPED` 的根因,激活 tracker 子模块

---

## 1. 背景

docs/51 交付的 trace 显示真机首屏 **cmd 1140071423 (d7.a)** 被调 436 次,是最高频 cmd。args 模式固定为:
```
(java.lang.Long 2038853396, byte[N], byte[2])
```

unidbg 黑盒模拟复现时:
- 对齐真机首次 args `(Long 2038853396, byte[30], byte[2])` 调用 d7.a
- **立即 crash: UC_ERR_FETCH_UNMAPPED** (ARM 跳到未映射地址)
- 推测: libtiny 内部用 Long arg 作为某个函数指针表的 key/index,表内容未在 unidbg 里 populate

**tracker 模块 (JSON `"t":{...}` 字段) 很可能由 d7.a 的这些前几次调用 seed**。d7.a 跑不通 → tracker 永远不激活 → JSON 少 47B → mua 短 383B → 3/5 端点 silent timeout。

---

## 2. 要抓的数据

对真机 Java_com_xingin_tiny_internal_t_a(cmd=1140071423, args=[Long, byte[N], byte[2]]) 的每次调用:

### Level 1 (必要): args 完整 hex dump

```json
{
  "seq": 0,
  "ts_ms": 0,
  "cmd": 1140071423,
  "long_arg": 2038853396,
  "long_arg_hex": "0x79881d14",
  "byte1_len": 30,
  "byte1_hex": "0102030405...",   // 完整
  "byte2_len": 2,
  "byte2_hex": "0102"
}
```

只要前 50 次的完整 byte[] 内容。byte[N] 和 byte[2] 的值可能暴露**业务语义**(是 session key? 是 magic header? 是网络请求的 URL path 的 hash?)—— 帮我推断 libtiny 内部把 Long 当成啥 table key 使.

### Level 2 (高价值): hook d7.a 内部 ARM 执行

在 d7.a **内部** (cmd dispatcher 分支到 1140071423 处理函数后) 装一个 native hook,看它:

1. 读 Long arg 后做的第一次 memory access 在哪个地址
2. 那个地址是否属于 libtiny 的 `.data`/`.bss` segment
3. 读出的值是否是函数指针 (指向 libtiny `.text` 区内另一个函数)

需要 shadowhook 或 xposed 的 native hook 能力 (现有 `lsposed/xhs-capture/jni/` 里有 shadowhook)。

**最简实现**: shadowhook 在 `Java_com_xingin_tiny_internal_t_a` 入口注册一个 interceptor,检查 r2 (cmd),如果 r2==0x43f41bff (1140071423),就 trace 后续 20 条 ARM 指令看查表逻辑。

如果 Level 2 难做,Level 1 already give me 50 hex dump 够我搞清楚了。

### Level 3 (可选,最后兜底): d7.a 的 return value

d7.a 返 jobject — 真机返的是什么? null / Integer / String / 自定义类?
这帮我推断 d7.a 是 "metric 上报" 还是 "query 查询"。

---

## 3. LSPosed 扩展点 (复用 docs/51 已有代码)

### 3.1 Hook 点与 docs/51 一致

```java
XposedHelpers.findAndHookMethod(
    "com.xingin.tiny.internal.t", cl,
    "a", int.class, Object[].class,
    new XC_MethodHook() {
        @Override protected void beforeHookedMethod(MethodHookParam param) {
            int cmd = (Integer) param.args[0];
            if (cmd != 1140071423) return;  // only d7.a

            Object[] args = (Object[]) param.args[1];
            // args[0] = Long, args[1] = byte[], args[2] = byte[]
            // dump full hex
            ...
            writeD7Line(seq, cmd, args);
        }

        @Override protected void afterHookedMethod(MethodHookParam param) {
            // Level 3: record return
        }
    });
```

### 3.2 byte[] hex dump 辅助

```java
private static String hex(byte[] b) {
    if (b == null) return "null";
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte v : b) sb.append(String.format("%02x", v & 0xff));
    return sb.toString();
}
```

### 3.3 输出路径

```
/data/data/com.xingin.xhs/files/d7_table.jsonl
```

pull 到 `lsposed/xhs-capture/captures/d7_table_<ts>.jsonl`,和 docs/51 的 pipeline 一致。

### 3.4 运行步骤 (同 docs/51)

```bash
cd lsposed/xhs-capture
./build.sh && adb install -r build/xhs-capture.apk
adb reboot && adb wait-for-device
adb reboot && adb wait-for-device  # double reboot per docs/43
adb shell input keyevent 82
adb shell 'am force-stop com.xingin.xhs'
adb shell 'su -c "rm -f /data/data/com.xingin.xhs/files/d7_table.jsonl"'
adb shell 'monkey -p com.xingin.xhs -c android.intent.category.LAUNCHER 1'
sleep 40
adb shell 'su -c "cp /data/data/com.xingin.xhs/files/d7_table.jsonl /sdcard/ && chmod 666 /sdcard/d7_table.jsonl"'
TS=$(date +%s)
adb pull /sdcard/d7_table.jsonl lsposed/xhs-capture/captures/d7_table_${TS}.jsonl
```

**数量限制**: d7.a 真机首屏 436 次,只抓前 50 次足够 (cap seq < 50 early return)。避免产 140MB 的 hex dump 文件。

---

## 4. 我拿到数据后做什么

### 4.1 看 Long arg 数值是否 drift

真机首次都是 `2038853396` 吗?还是每次不同?如果每次不同,那这个 Long 是**动态**生成的 (时间/计数器 hash),unidbg 侧需要复刻生成逻辑。

### 4.2 看 byte[N] 内容推断业务

- 是否是 UTF-8 可读字符串片段 (HTTP URL path 的 hash? request header name?)
- 是否是纯随机字节 (session entropy)
- 是否有固定前缀/magic

### 4.3 对照 ARM .data/.bss

拿 Long arg 的值 (若固定 2038853396) 去 libtiny ELF 里 grep `.data`/`.bss` 段:
```bash
python3 -c "
d=open('libtiny.so','rb').read()
v = (2038853396).to_bytes(4,'little')
idx=d.find(v)
while idx >= 0:
    print(f'0x{idx:x}: {d[max(0,idx-8):idx+16].hex()}')
    idx=d.find(v, idx+1)
"
```

找到存储位置 → 反查 xref → 找到 populate 这个值的代码 → 在 unidbg 里手动 populate 对应位置的 .bss。

### 4.4 最终业务验收 (unidbg 侧, 我负责)

拿到数据 + populate .bss 后重跑 MuaTailProbeTest:
- d7.a 调用不再 crash
- JSON 出现 `"t":{c:0,d:0,f:0,s:4098,t:0,tt:[]}`
- mua 从 1165B → 接近真机 1548B
- live server endpoint 从 2/5 → 3/5+

---

## 5. 交付验收 (另一窗口完成的判定标准)

你交付时请自测以下,任一不满足就别发 —— 发了我也要退回:

### 5.1 文件存在性
- [ ] 产出文件 `lsposed/xhs-capture/captures/d7_table_<ts>.jsonl` 存在且 ≥ 1 KB
- [ ] 文件权限可读 (pull 过程无 Permission denied)

### 5.2 数据完整性 (Level 1 必要)
自测命令:
```bash
F=lsposed/xhs-capture/captures/d7_table_<ts>.jsonl
echo "总行数:"; wc -l $F
echo "cmd==1140071423 行数:"; grep -c '"cmd":1140071423' $F
echo "有 long_arg 字段:"; grep -c '"long_arg"' $F
echo "有 byte1_hex 字段:"; grep -c '"byte1_hex"' $F
echo "有 byte2_hex 字段:"; grep -c '"byte2_hex"' $F
```

全部要 **≥ 30** (希望 50, 真机冷启一般 50 次 d7.a 都够)。如果 < 30:检查 hook 是否装上 / TINY_CMD_MAX 是否限制过早。

### 5.3 hex 格式有效
```bash
python3 -c "
import json
with open('$F') as f:
    for i, line in enumerate(f):
        d = json.loads(line)
        b1, b2 = d['byte1_hex'], d['byte2_hex']
        assert all(c in '0123456789abcdef' for c in b1), f'line {i} byte1 invalid hex: {b1[:40]}'
        assert all(c in '0123456789abcdef' for c in b2), f'line {i} byte2 invalid hex: {b2[:40]}'
        assert len(b1) == d['byte1_len'] * 2, f'line {i} byte1_len mismatch'
        assert len(b2) == d['byte2_len'] * 2, f'line {i} byte2_len mismatch'
print('hex valid')
"
```

### 5.4 Long arg 统计 (帮我快速判定)

```bash
python3 -c "
import json, collections
longs = []
with open('$F') as f:
    for line in f:
        longs.append(json.loads(line)['long_arg'])
c = collections.Counter(longs)
print(f'unique long values: {len(c)}')
print(f'top 3: {c.most_common(3)}')
"
```

**关键发现**:
- 如果 unique == 1 (全 2038853396) → Long 是常量 jmethodID-like hash,指针表是**静态**,我 unidbg 侧 populate .bss 就行
- 如果 unique > 1 → Long 是动态计算,需要 Level 2 trace 看生成逻辑 → 发 L2 版本

**把上面 3 行脚本输出也贴在交付简报里**,不让我手工跑一遍。

### 5.5 byte1 内容 sanity check

随便挑 3 条看 byte1_hex 首 16 字节 (32 hex chars):
```bash
python3 -c "
import json
with open('$F') as f:
    for i, line in enumerate(f):
        if i >= 3: break
        d = json.loads(line)
        print(f'seq={d[\"seq\"]} long={d[\"long_arg\"]} b1[:16]={d[\"byte1_hex\"][:32]} b1_len={d[\"byte1_len\"]}')
"
```

如果 byte1 看起来是**可读字符串** (hex → ASCII 有意义) 或**固定 magic prefix**,都算合格数据 — 告诉我即可,有信息量。
如果全是**随机字节**(没前缀,每次都不同)也告诉我 — 方向就转向 L2。

### 5.6 环境声明 (简报必写)

简报 (可以就是文件开头 5 行 README) 必须包含:

- [ ] hook 日期 / Android 版本 / xhs 版本号
- [ ] xhs 启动模式: force_stop 冷启 / attach 已开
- [ ] 有没有登录账号 (影响 did / session)
- [ ] 抓到前 Ctrl-C 时机 (首屏? 滑了几条? 点了哪个页面?) — 这影响 cmd 序列
- [ ] hook 是否只装在 main process (vs 漏装或多进程跑重)
- [ ] 异常/中断记录 (有 app crash? hook throw 过?)

少了这些我分析时会做出错误假设。docs/51 就做得不错,照抄 §2 那种风格即可。

### 5.7 L2 / L3 可选 (加分项, 不强制)

Level 2 (ARM trace) 或 Level 3 (return value) 做到就做,做不到直接说做不到,我不会因此退回 L1。

---

## 6. 交付快速 checklist

```
[ ] 文件 lsposed/xhs-capture/captures/d7_table_<ts>.jsonl 存在
[ ] >= 30 行 cmd=1140071423 记录
[ ] 每行 long_arg / byte1_hex / byte2_hex 齐全且 hex 有效
[ ] 附 unique long values 统计输出
[ ] 附环境声明 (版本/启动模式/登录/抓到点)
[ ] (可选) L2 / L3 数据
```

如果 checklist 全绿,发简报 + 文件路径给我就完事。我接手。

---

## 7. Fallback: 如果你觉得 Level 2 太难

Level 1 (args hex dump) 就够我很多信息。极端简化方案:

```java
// 在 xhs-capture 里加 5 行
if (cmd == 1140071423 && seq < 50) {
    Object[] args = (Object[]) param.args[1];
    long longArg = (Long) args[0];
    byte[] b1 = (byte[]) args[1];
    byte[] b2 = (byte[]) args[2];
    writeLog(String.format("d7.a[%d] long=%d b1(%d)=%s b2(%d)=%s",
        seq, longArg, b1.length, hex(b1), b2.length, hex(b2)));
}
```

写到 xhs_capture.log 就行,不用独立 jsonl。甚至可以直接 tail 你手动粘贴给我。

---

## 8. 一句话总结

**抓真机 libtiny d7.a 前 50 次调用的完整 args hex (Long + 两个 byte[]),让我查出 libtiny 内部 Long→指针表的存储地址,然后在 unidbg 里 populate 那个表 → d7.a 跑通 → tracker 激活 → mua 到位。**

预计交付后我这边 1-2 小时内可以完成 unidbg 侧改动并回测。

---

## 9. Why this is on-direction

- 纯观测 (hook log),不改 xhs app 逻辑
- 用项目已验证的 LSPosed 路径 (`lsposed/xhs-capture`)
- 拿到的信息用来**补 unidbg 环境** (populate .bss / .data 对应字节),让 libtiny 自己 init 自己 run
- 不合成任何假数据喂给 libtiny
- 不 stub / short-circuit libtiny 内部任何函数

完全符合 unidbg 黑盒模拟大方向。
