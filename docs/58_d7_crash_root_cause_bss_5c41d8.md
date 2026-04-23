# 2026-04-18 EOD4 d7.a crash 根因锁定到 .bss+0x5c41d8

## Call chain 完整追踪

从 docs/57 继续, 加 EventMemHook + CodeHook 在 libtiny+0x96000 抓数据:

### crash 的 ARM 指令序列 (libtiny+0x95ff6..0x9600c)

```
+0x95ff6: LDR.W r0, [r0, #0x354]   ; r0 = *(stack + 0x354)
+0x95ffa: LDR   r0, [r0]            ; r0 = *(libtiny+0x5c41d8)  ← 这里 load 0
+0x95ffc: LDRD  r1, r2, [r1, #0]    ; r1,r2 = *r1 pair
+0x96000: EOR   r2, r0, r1           ; r2 = 0 XOR 0x79866f14 = 0x79866f14
+0x96004: LDR.W r0, [r6, #0xd4]      ; load arg1 to function
+0x96008: LDR.W r1, [r6, #0xc4]      ; load arg2
+0x9600c: BLX   r2                    ; call function @ 0x79866f14 = unmapped
```

### 实测数据 (probe)

```
PROBE 0x95ff6 #1: r0=0xbfffed14 (stack), [r0+0x354]=0x408441d8 ← 对的
PROBE 0x95ffa #1: r0=0x408441d8 = libtiny+0x5c41d8, [r0]=0x00000000 ← ★ 这里 0 ★
EOR-probe #1: r0=0 r1=0x79866f14 XOR=0x79866f14 → crash
```

## 根因

**libtiny .bss 的 0x5c41d8 位置**应该 store 一个 heap pointer, 指向含 XOR 解密 mask 的 struct。
**unidbg 里这个 slot 是 0**, 因为 libtiny 内部某段 init 代码 (malloc struct + 写 bss) 没执行。

### .bss 信息 (ELF)

```
.bss section: addr=0x5c3ec0, size=0xbef0 (47856 bytes)
0x5c41d8 - 0x5c3ec0 = 0x318 (offset 792 within .bss)
```

## 为什么 .bss slot 0x5c41d8 没被填

尝试过:
1. ✗ 默认运行 — 0
2. ✗ SKIP_INIT_PATCH=1 (让 libtiny 真 init) — 还是 0
3. libtiny 的 .init_array 有 84 个构造函数 (addr 0x703dd..0x806b5), 某些应该 write 这个 slot
4. 可能 unidbg 没执行完所有 init_array, 或某个构造函数依赖缺失环境 (比如特定系统 property / 线程 / JVM 状态) 跑一半就 return

## 3 条剩余方向

### 方向 1: 深反汇编 84 个 .init_array 找 writer
- **成本**: 1-2 周 (OLLVM 混淆, 每个 constructor 都可能几百条指令)
- **产出**: 纯黑盒, 永久解决
- **风险**: 找到的 writer 可能依赖 unidbg 不模拟的东西, 又要补环境

### 方向 2: 直接 mem_write 0x5c41d8
- **成本**: 2h
- **技术**: 从 user 的真机 memory dump 读 .bss 完整 bytes, mem_write 到 unidbg
- **风险**:
  - 跨进程 heap pointer 地址不可移植 (真机 0x7d85xxxx 在 unidbg 没对应)
  - 可能需要配套 allocate 相应 struct

### 方向 3: Manually populate 关键 .bss 槽位 (半黑盒)
- **成本**: 半天
- **步骤**:
  1. 在 unidbg 里 malloc 0x100 字节
  2. fill with plausible bytes (先 0 试试)
  3. 写指针到 lib+0x5c41d8
  4. 跑 d7.a 看是否 crash 其他地方 (说明 slot populate 对了)
  5. 迭代对每个 crash 点填

## 今日结论

**ARM level 的 root cause 已定位到字节级**。从这里往下走要么:
- 1-2 周纯黑盒 (深反汇编)
- 半天半黑盒 (手动 populate)
- 或 accept 2/5 天花板 (这是今日诚实路径)

memory 已记录 `project_2of5_final_ceiling_confirmed`, 该 note 可补充 "crash at libtiny+0x96000, .bss+0x5c41d8 populate missing"。
