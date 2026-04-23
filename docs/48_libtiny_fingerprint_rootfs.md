# 2026-04-18 libtiny 指纹黑盒补环境 (fake_rootfs)

## 关键发现: memory note "vfork + /proc/self/stat" 是错的

`project_libtiny_reflection_stubs_missing` 之前claim 192B 差距来自 `native /proc/self/stat + vfork + waitpid`。SYSCALL_TRACE 实测证伪:

- vfork 一次**都没有**在 sign() 期间调用 (我们的 PLT hook 计数为 0)
- libtiny **从不** 读 `/proc/self/stat`
- 实际读的是**其他 30+ 路径**做设备指纹

## 真实 libtiny sign() 探测路径 (30 个)

| 类别 | 路径 | 数量 |
|---|---|---|
| 设备指纹 | `/system/build.prop`, `/proc/stat`, `/dev/urandom`, `/dev/__properties__` | 4 |
| 标准目录存在性 | `/bin`, `/data`, `/etc`, `/init`, `/sdcard`, `/system` | 6 |
| 应用路径 | `/data/data/com.google.android.gms/code_cache`, `/data/user/0/*/code_cache` | 2 |
| 系统态 | `/data/system/last-header.txt`, `/data/system/packages-warnings.xml` | 2 |
| 存储状态 | `/data/misc_ce`, `/data/system_ce`, `/data/vendor_ce`, `/data/vendor_ce/0` | 4 |
| 媒体目录 | `/storage/emulated/0/{Alarms,Download,Movies,Music,Notifications,Pictures,Podcasts,Ringtones}` + `.nomedia` | 10 |
| libtiny 缓存 | `/.tistore`, `/.tistore.tmp`, `/sdcard/Download/ks.sr0`, `/sdcard/Download/ks.sr0.tmp` | 4 |

## 修复方案: `setRootDir(fake_rootfs)`

核心改动 `XhsCombinedSigner.initialize()`:
```java
java.io.File rootfsFile = new java.io.File("fake_rootfs");
if (!rootfsFile.exists()) rootfsFile = new java.io.File("unidbg-xhs/fake_rootfs");
emulator = AndroidEmulatorBuilder.for32Bit()
        .setProcessName("com.xingin.xhs")
        .setRootDir(rootfsFile)
        .build();
```

`fake_rootfs/` 内容:
- `system/build.prop` — 真机 getprop 输出 5123B
- `proc/stat` — 真机 /proc/stat 1672B
- `data/system/last-header.txt` — 真机 513B
- `data/system/packages-warnings.xml` — 真机 140B
- `storage/emulated/0/Download/ks.sr0` — 真机 4028B
- `sdcard/Download/ks.sr0` — 同上副本
- 空目录占位: `/bin /etc /data /data/data /data/user/0 /storage/emulated/0/* ...`

## 实测数据

### mua length 单调变化

| rootfs 版本 | mua 总长 (B) |
|---|---|
| 无 rootfs | 1102 |
| rootfs (dir 占位) | 1124 (+22) |
| rootfs (真内容) | 1165 (+63) |
| **真机目标** | **1058** |

**证明**: libtiny 对 fake_rootfs 文件内容敏感,黑盒补环境路子通。但当前**过量 107B**,需要精调。

### 服务器行为变化

| rootfs 版本 | 200 | 406 拒 | 上游 timeout |
|---|---|---|---|
| 无 | 2 | **3 (直接 reject)** | 0 |
| 有 | 2 | **0** | 3 |

406 消失了 — 服务器不再"一眼看出签名形式错误"。但 timeout 说明仍有内容层 flagging。

## 下一步 (待做)

### 精调 fake_rootfs 降 107B

候选方案:
- `build.prop` 裁剪: libtiny 可能只读特定 props, 只保留必要行
- `ks.sr0` 4028B 可能是 XHS 自己累计的历史 state (非跨设备共享的指纹), 改返空文件
- `.tistore` 持久化导致累加: 每次运行先清空

### 持久化 proxy 稳定

`adb shell app_process -Djava.class.path=/data/local/tmp/proxy.dex /system/bin PhoneProxy`
配上自动 restart daemon,不要每次都崩。

## Why + How to apply

**Why**: libtiny 做的是 **Android 设备环境指纹**,不是进程级 fork 数据。"补环境"意味着把 /system/build.prop /proc/stat /data/system/* 等用真机 snapshot 填 fake_rootfs,unidbg 看起来就像真 Android。

**How to apply**:
- 任何新 signer 先跑 `SYSCALL_TRACE=1` 看 libtiny 读了啥
- `fake_rootfs/` 用真机 snapshot 填,不要自己编内容
- `/bin /etc /init /sdcard` 在真机是 symlink,unidbg rootDir 的 symlink resolve 有坑,用 empty dir 替代更稳
