# docs/44 — 真机 cPtr 内存 dump 需求(精准版)

**Responds to**: 主项目 unidbg 侧 main_hmac 黑盒生成卡点
**Companion**: `docs/42_hook_main_hmac_writer_stack.md`(已交付 `docs/43`)
**目标**: 拿到真机 `libxyass` `Native.intercept` 入口时的 `cPtr` 内存快照,unidbg 侧对比 diff,找"缺哪个 JNI stub 让 derive 分支被 skip"

---

## TL;DR

就一条 hook:

1. hook `libxyass.so` export 的 **`Java_com_xingin_shield_http_Native_intercept`**(native 方法,shadowhook/frida/inlinehook 任选)
2. 在 enter 时读 **第二个 Java 参数** (long cPtr) 指向的 **0x200 字节**,十六进制 dump
3. 连抓 **3 次**不同 request(看哪些 byte 稳定、哪些随 request 变)
4. 一次记录就够了,不需要跑 fresh install;**只要 xhs 已登录 + 主进程跑起来即可**

输出: `scratch/persistent_survey/cptr_dump.log`

---

## 背景极简

我 unidbg 黑盒跑通了 `xyass.intercept` 产 shield(byte-exact 对齐真机),但 `Native.intercept` 内部**没触发 main_hmac 的 derive + putString** 分支。真机做了,我们没做。

我已经穷尽 Java 侧输入(URL/Chain/Request/headers),还是 skip。推测差距在 **native 内部某个 cPtr 字段**(cPtr 是 `Native.initialize("main")` 返回的 long handle,intercept 每次调用都作为第二个参数传回)。

拿到真机 cPtr dump,我 diff 出不同字段,**反推是哪个 JNI stub 在 unidbg 里返了错值**,补 stub → native 自己填对 cPtr → derive 分支自然触发 → 我的 spMap.putString hook 自动捕获 main_hmac → 删掉硬编码。

---

## Hook 规格

### 插桩点

`libxyass.so` 里的 **`Java_com_xingin_shield_http_Native_intercept`** 这个 JNI 导出符号。

动态查找地址(每次进程启动 base 不同):

```c
void *hdl = dlopen("libxyass.so", RTLD_NOW);
void *entry = dlsym(hdl, "Java_com_xingin_shield_http_Native_intercept");
```

或用 shadowhook `shadowhook_hook_sym_name("libxyass.so", "Java_com_xingin_shield_http_Native_intercept", ...)`。

### JNI 参数布局

ARM32 Native 方法签名:
```
jobject Java_com_xingin_shield_http_Native_intercept(
    JNIEnv *env,       // r0
    jclass  clazz,     // r1
    jobject chain,     // r2  (okhttp3.Interceptor$Chain)
    jlong   cPtr)      // r3(low 32) + [sp, #0](high 32), but libxyass 32-bit so 只用 r3
```

**32-bit ARM ABI 对 jlong**:参数 3(jlong)占 **r2+r3** 一对寄存器(或 r3 + stack),但前面还有 env/clazz 所以具体落在:
- env = r0
- clazz = r1
- chain = r2
- cPtr_low = r3
- cPtr_high = [sp+0]

或者可能因 alignment 落到 r2+r3,把 chain 挤到 [sp] —— 不同 compiler 行为不同。**实际读出来看**:

```c
// 方法一:直接按 r3 读(假设 low 在 r3)
uint32_t cptr_low = regs->r3;
// 方法二:按 [sp+0], [sp+4] 读
uint32_t sp0 = *(uint32_t*)regs->sp;
uint32_t sp4 = *(uint32_t*)(regs->sp + 4);
// dump 三个候选,让我看哪个是真 cPtr(我 unidbg 里 cPtr ~ 0x402520f0 级别,是个 heap 指针)
```

**更简单的办法**: hook 里直接调用 `env->GetDoubleField` 风格不合适。干脆 **hook 的同时从 Java 层** `XhsHttpInterceptor.intercept(Chain chain)` 的 `this.cPtr` 字段读。这是 Java `long` field,用 `XposedHelpers.getLongField(thisObj, "cPtr")` 稳定拿到。

**推荐**: hook `com.xingin.shield.http.XhsHttpInterceptor.intercept(okhttp3.Interceptor$Chain)` 的 **beforeHookedMethod**:

```java
XposedHelpers.findAndHookMethod(
    "com.xingin.shield.http.XhsHttpInterceptor", cl,
    "intercept", "okhttp3.Interceptor$Chain",
    new XC_MethodHook() {
        @Override protected void beforeHookedMethod(MethodHookParam param) {
            long cPtr = XposedHelpers.getLongField(param.thisObject, "cPtr");
            // 用 dlsym + 读内存方式 dump 0x200 字节
            byte[] mem = readNativeMem(cPtr, 0x200);
            log("[cptr-dump] cPtr=0x" + Long.toHexString(cPtr) + " request_url=" 
                + ((okhttp3.Request)XposedHelpers.callMethod(param.args[0], "request")).url().toString()
                + " hex=\n" + hexdump(mem));
        }
    });
```

`readNativeMem` 简单实现:

```java
static byte[] readNativeMem(long addr, int len) {
    // 用 ProcessMaps / /proc/self/mem 读自己进程
    try (RandomAccessFile f = new RandomAccessFile("/proc/self/mem", "r")) {
        f.seek(addr);
        byte[] buf = new byte[len];
        f.read(buf);
        return buf;
    } catch (Exception e) { return new byte[0]; }
}
```

(如果 /proc/self/mem seek 有权限问题,用 JNI 直接 memcpy。但 xposed 进程 UID = xhs 的 UID = 10331,读自己内存不需要 root。)

### Hexdump 格式

```
[cptr-dump] ts=... cPtr=0x765a2e8030 request_url=https://edith.xiaohongshu.com/api/...
  +0x000  de ad be ef 00 00 00 00 | <ascii>
  +0x010  ...
  +0x020  ...
  ...(32 行,共 0x200 字节)
```

### 抓取次数

**3 次不同 request**:
1. 第一次是 app 启动第一个 signed request(可能是 flag_exp)
2. 第二次是登录后某个 edith API
3. 第三次是发笔记/feed 相关

这样能看出:
- 哪些字段**每次 intercept 都相同**(就是 init 时设好的 device-bound state → 我们 unidbg 应该对齐)
- 哪些字段**每次都变**(runtime state/counter → 不需要对齐)

---

## 输出交付

```
scratch/persistent_survey/cptr_dump.log      (3 次 dump,总 ~20 KB)
```

每次 dump 一个 block,格式见上。

---

## 我拿到数据后的动作

1. 立即在 unidbg 同样位置 dump 我自己的 cPtr
2. byte-by-byte diff
3. 对每个不同字段:
   - 反汇编 xyass 找**哪条指令写该 offset**
   - 那条指令上游(通过 env->CallXXXMethod)读哪个 Java API
   - 补该 JNI stub 返回正确值
4. rerun,diff 收敛
5. 理论上 diff 完全收敛后 Native.intercept 会走 derive 分支,spMap 自动捕获 main_hmac,删硬编码

---

## 大方向自查(黑盒)

这条 hook **只读不改真机**,拿到的 cPtr 数据**不会被直接 mem_write 到 unidbg**(那是白盒)。
我会把 diff 用作**"哪个 JNI stub 缺了"的线索**,补正确的 stub,**让 unidbg 里 app 代码自己生成对的 cPtr**。

类比已落地的 `signatureHashCode = 0x4cdc059d` stub — 真机值用作 stub 的实现,native 代码自己算出 cPtr 的衍生字段。

---

## 时间预算

- hook 编写: ~20 行代码,10 分钟
- deploy + reboot: 5 分钟
- 抓 3 次 request: 2 分钟
- pull log: 1 分钟

**总计约 20 分钟**,比 docs/42(putString stack trace) 更简单,因为不需要 uninstall/reinstall 触发特殊时序。

---

## 卡壳点兜底

若 `readNativeMem` via `/proc/self/mem` 不能读(SELinux 或地址保护),退路:

```java
// 写 JNI 小 helper
static native byte[] readAt(long addr, int len);
// loadLibrary native lib,里面 memcpy((void*)addr, buf, len)
```

或者直接在 hook 入口调用 `shadowhook` 或 `memcpy` 风格 C API。

如果真遇到读不到就反馈,我改用另一种方法(比如 trace CallObjectMethodV 参数)。
