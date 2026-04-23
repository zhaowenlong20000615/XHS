# 2026-04-18 EOD5 d7.a 深度 trace — OLLVM flatten 阻碍

## 推进步骤汇总

本轮增加 4 个 hook 系统:
- `MEM_FAULT_TRACE=1` 抓 UC_ERR_FETCH_UNMAPPED
- `D7_EOR_PROBE=1` 抓 lib+0x96000 EOR 前 r0/r1
- `BSS_WRITE_TRACE=1` 抓 libtiny .bss 所有写入
- `STACK_SLOT_TRACE=1` 抓 0xbffff040 附近栈写入
- `BSS_SRC_PROBE=1` 抓 LDRD 前 r1 源地址

## 结论链

1. **Crash site**: lib+0x96000  
   ```
   EOR r2, r0, r1          ; r2 = r0 XOR r1 = 真函数地址
   BLX r2                   ; crash: r2 = 0x79866f14 unmapped
   ```

2. **r0 来源**: `*(*(stack + 0x354))` 两次 deref
   - 第一次: stack[0x354] = `0x408441d8` (lib+0x5c41d8, .bss slot) ✓
   - 第二次: `*(lib+0x5c41d8)` = **0** in unidbg (应是非零)

3. **r1 来源**: `*(stack_slot_A)` where stack_slot_A = 0xbffff058
   - `*(0xbffff058)` = (0x79866f14, 0x37e62ddf)
   - r1 = 0x79866f14, r2_discarded = 0x37e62ddf

4. **0x5c41d8 被 lib+0xb180a STRD 写 0** — 源是 stack 0xbffff040 内容 (0, 0)

5. **0xbffff040 = 0 是 libtiny 故意写**:
   - STACK-WRITE #2: PC=lib+0x9c9d0 写 0 到 0xbffff040
   - STACK-WRITE #3: PC=lib+0x9c9d0 写 0 到 0xbffff044  
   - STACK-WRITE #4: PC=lib+0x9c9d0 写 dest_addr 0x408441d8 到 0xbffff048
   - 之间没有任何 writes
   - 所以 libtiny 代码本身 INTENT 写 0 到 .bss

6. **真机同代码路径若也写 0, 也会 crash**. 所以真机执行 **不同的代码路径** 到达 .bss store 时, 那条路径 STR 非零值。

7. **OLLVM 控制流 flatten 阻碍静态分析**:
   - lib+0x9c9ce: `MOV PC, r1` — 动态跳转
   - lib+0x9c9d0: 之后的指令看起来是 LDR (不是 STR), 但 WriteHook 报 PC 在此
   - WriteHook PC 实际指向"基本块入口", 真 STR 在通过动态跳转到达的另一 block

## 为什么现在没办法简单修

OLLVM 把控制流打散成 ~100+ 个基本块, 每块都以 `MOV PC, Rx` 结尾。
每次 Rx 的值取决于多个 register + memory 的 XOR/ADD 组合。

静态 disasm 看到 lib+0x9c9d0..0x9c9f0 像是 "一段代码", 实际执行时可能完全不走这条线。

要搞清楚真机和我们 unidbg 在哪一步分叉, 需要:
1. BlockHook 输出 block 执行序列 (可能几百条)
2. 真机上同样 hook 做对比 (LSPosed + shadowhook 能做)
3. 找 first divergent block
4. 定位到那个 block 的条件,补环境让我们走同样路径

## 估算

这是 A 方案的下层。做完 **预计 5-10 天** (OLLVM flatten 逆向有经验的人):
- 写 BlockHook infra: 半天
- 对比真机/unidbg block: 1-2 天
- 找 divergence 环境条件: 2-5 天
- 验证 d7.a 能跑通 + mua 达 1337B: 1-2 天

## 建议

此处是真正的 "1-2 周" 起点. 已经走了 3 天在 unidbg 黑盒路, 产出:
- 2/5 live server baseline 稳
- libtiny + xyass 6 签名 header 全出
- 一整套真机-unidbg 对比 infra (fake_rootfs, UnidbgPatcher, 5 个 debug hooks)
- 最终 ceiling 定位到 OLLVM flatten 控制流分叉 (不可简单修)

继续 A 要换更长时间 block 去做. 或者接受 2/5 作为当前版本.

下一步 (如要继续):
1. 实现 BlockHook: 记录每个 block 入口 PC + 入参 register → jsonl 
2. 让另一窗口在真机做同样 block trace (仅 cmd=1140071423 first call 期间)
3. diff 两边第一个 block 分叉位置
