# 2026-04-18 UnidbgPatcher JPMS 修复 + mua/shield 恢复

## 症状

默认硬塞模式下 `XhsCombinedSigner.sign()` 返 `mua=null` + `shieldHeaders.size=0`。log 里 11+ `jmethodID is null` NPE 来自 `DalvikVM$35/$47/$53` (Call*MethodV) 处理 Float/Boolean/okio autoboxing。

## 根因 1: UnidbgPatcher 被 JPMS 反射限制 block

`UnidbgPatcher.patch()` 用 javassist 运行时给 unidbg `DalvikVM$35/$47/$53` 等 Call*MethodV handler 插入 jmethodID null-check fallback (autoboxed Float/Boolean/Integer 返 primitive 值)。

但 `cc.toClass()` 需要反射访问 `ClassLoader.defineClass`:
```
[patch] failed: Unable to make protected final java.lang.Class
  java.lang.ClassLoader.defineClass(...) accessible:
  module java.base does not "opens java.lang" to unnamed module @d524862
```

pom.xml 里的 `<options>` 在 exec:java 场景不生效 (exec:java 共享 Maven outer JVM,flag 必须在 outer JVM 上)。

### 修复

`unidbg-xhs/.mvn/jvm.config`:
```
--add-opens=java.base/java.lang=ALL-UNNAMED
--add-opens=java.base/java.lang.reflect=ALL-UNNAMED
--add-opens=java.base/jdk.internal.loader=ALL-UNNAMED
```

成功后 log 开头必有:
```
[patch] unidbg DalvikVM CallXxxMethodV handlers patched
[patch] ArmLD$7 (dl_unwind_find_exidx) → returns real .ARM.exidx
[patch] DalvikVM$162 (ReleaseStringUTFChars) → no-op (in loop)
[patch] DalvikVM$179/$180 (GetByteArrayElements/Release) → reusable buffer
```

## 根因 2: okio.Buffer.read([B)I stub 缺失

xyass intercept 调 `chain.proceed()` → `response.body()` → `okio.Buffer.read(byte[])` 读 response body。默认 AbstractJni 抛 UnsupportedOperationException → xyass intercept 中断 → shield 空。

### 修复

`XhsCombinedSigner.handleInt` switch 加一条:
```java
case "okio/Buffer->read([B)I": return -1;  // EOF = 空 body
```

## 修完后状态

| Header | 状态 |
|---|---|
| `x-mini-mua` | ✅ 出 (tail 576B) |
| `shield` | ✅ 出 |
| `xy-platform-info` | ✅ 出 |
| head4 | stateless — 同 URL 反复 sign 返同 head4 |

head4 stateless 可能**是正确行为** — SP_TRACE 证实 libtiny 在 sign() 期间**从不调** `SharedPreferences.getString('main_hmac')`。main_hmac 只在 `Native.initialize` + bootstrap 时被 xyass 读过一次。同 URL 同 session 产同 head4 是预期。

## 未验证

- live server 2/5 → N/5 (PhoneProxy 当时 down,没测)
- NATIVE_DERIVE_HMAC=1 vs 硬塞 mode 的 endpoint 接受差异

## 相关 log

`scratch/2026-04-18_unidbg_patcher_fix/`:
- `with_patch.log` — 加 MAVEN_OPTS 首次成功的完整 verbose
- `persist.log` — `.mvn/jvm.config` 持久化验证
- `sp_trace.log` — `SP_TRACE=1` 观察 getString/putString 调用时序
- `native_derive.log` — `NATIVE_DERIVE_HMAC=1` 模式
- `head4_diag.log` — 3 iter 对比 head4 stateless 的 verbose JNI

## Why + How to apply

**Why**: 大方向是 unidbg 黑盒模拟,"缺啥补啥"。UnidbgPatcher 是关键的"补环境"工具,不加 flag 时它**默默失败**,一切 downstream 崩坏但看似随机。

**How to apply**:
- 任何 `unidbg-xhs` 子项目跑前先确认 `.mvn/jvm.config` 存在且生效
- 测试开头必看 `[patch] unidbg DalvikVM CallXxxMethodV handlers patched` 这行;没这行 patch 没应用
- 补 JNI stub 优先改 `handleInt/handleObject` 集中 switch,而非散落的 callXxxMethod 覆盖
