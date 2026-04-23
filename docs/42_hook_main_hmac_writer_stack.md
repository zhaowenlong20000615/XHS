# Precise hook: capture who writes main_hmac

## 动机

`findings.md` 证实 main_hmac 是 app 用 device-fixed 种子派生,每次 fresh install 产同值。
unidbg 主线的黑盒方案需要**找到生成入口**,在 emulator 里复现同一条代码路径。

不需要 derivation 算法、不需要全量 crypto trace,**只需要一条信息**:
> **谁调用了 `SharedPreferences$Editor.putString("main_hmac", ...)` ?**

拿到这个调用栈 → unidbg 侧照搬调 Java 入口 → 自动触发 native 生成 → spMap 自动捕获 → 零硬编码。

---

## Hook 规格

**Hook 点**: `android.app.SharedPreferencesImpl$EditorImpl.putString(String, String)`
(Android 系统类,包名 fixed,不受 DexGuard 影响)

**触发条件**: **仅当 `key.equals("main_hmac")`**,其他 key 忽略。

**每次触发打印**:

```
[HOOK main_hmac_writer] ts=<millis>
  thread=<Thread.currentThread().getName()>
  value_prefix=<first 32 chars of value>
  value_len=<chars>
  stack=
    <整段 Thread.currentThread().getStackTrace() 打印, 至少 20 层>
```

**输出文件**: `/sdcard/main_hmac_writer.log`(只 append,不清空),完事 adb pull 到
`scratch/persistent_survey/main_hmac_writer.log`。

---

## Xposed/LSPosed 伪码参考

加到 `lsposed/xhs-capture/src/com/xhs/capture/XhsCapture.java` 或新建 hook:

```java
XposedHelpers.findAndHookMethod(
    "android.app.SharedPreferencesImpl$EditorImpl", loader,
    "putString", String.class, String.class,
    new XC_MethodHook() {
        @Override protected void beforeHookedMethod(MethodHookParam param) {
            String key = (String) param.args[0];
            if (!"main_hmac".equals(key)) return;
            String value = (String) param.args[1];
            StringBuilder sb = new StringBuilder();
            sb.append("[HOOK main_hmac_writer] ts=").append(System.currentTimeMillis()).append('\n');
            sb.append("  thread=").append(Thread.currentThread().getName()).append('\n');
            sb.append("  value_prefix=").append(value == null ? "<null>"
                    : value.length() > 32 ? value.substring(0, 32) : value).append('\n');
            sb.append("  value_len=").append(value == null ? -1 : value.length()).append('\n');
            sb.append("  stack=\n");
            StackTraceElement[] st = Thread.currentThread().getStackTrace();
            for (int i = 0; i < Math.min(30, st.length); i++) {
                sb.append("    ").append(st[i]).append('\n');
            }
            try (FileWriter fw = new FileWriter("/sdcard/main_hmac_writer.log", true)) {
                fw.write(sb.toString());
            } catch (IOException e) { /* ignore */ }
        }
    });
```

---

## 流程

```bash
# 1. 加 hook + 重新安装 LSPosed module + 重启
./lsposed/xhs-capture/deploy_and_dump.sh   # 或等价流程

# 2. 清 log
adb shell "rm -f /sdcard/main_hmac_writer.log"

# 3. uninstall XHS (清除 s.xml 强制重新生成)
adb uninstall com.xingin.xhs
adb install target/xhs.apk
adb shell monkey -p com.xingin.xhs 1

# 4. 等 60 秒让 bootstrap 跑完 (参考 findings.md 第 72 行: s.xml mtime = 启动 +45s)
sleep 60

# 5. pull log
adb pull /sdcard/main_hmac_writer.log scratch/persistent_survey/

# 6. 如果 log 为空,可能 main_hmac 早就存在(没触发 putString): 
#    先 rm s.xml:
#    adb shell "su -c 'rm /data/data/com.xingin.xhs/shared_prefs/s.xml'"
#    然后 am force-stop, 重开 app, 再试
```

---

## 预期产出的样子

```
[HOOK main_hmac_writer] ts=1776499200123
  thread=main
  value_prefix=9sQx+OUeOG4/W1OtYjlyPRNG6jZZ
  value_len=128
  stack=
    java.lang.Thread.getStackTrace(Thread.java:...)
    com.xingin.xxxxx.XxxSomething.initHmac(XxxSomething.java:...)   ← 关键! 
    com.xingin.yyyyy.BootInitializer.step3()
    com.xingin.zzzz.Application.onCreate()
    ...
```

**我需要的就是第 2 行以后的 `com.xingin.*` 栈**。即使被混淆成 `a.b.c.doSomething()`,我也能 jadx 反查。

---

## 交付

一个文件: `scratch/persistent_survey/main_hmac_writer.log`。
大小预计 < 2 KB(单次 putString 调用)。

拿到后我直接在 unidbg 里:
1. `vm.resolveClass("com/xingin/xxx/YyyClass")` 拉起那个 Java class
2. 用 javassist 或直接 `callObjectMethod` 调那个 `initHmac()`
3. 让 native 调用链跑完
4. spMap 捕获到 putString → 完成生成
5. 后续 libtiny `getString("main_hmac")` 自动命中

**大方向: unidbg 黑盒 = app 的代码在 emulator 里自己跑完,我们不逆算法**。

---

## 优先级

这一条 hook 能直接消灭 `XhsCombinedSigner.MAIN_HMAC_VALUE` 硬编码的需要。预计 10 分钟能完成一轮 adb + LSPosed + reboot + launch。
