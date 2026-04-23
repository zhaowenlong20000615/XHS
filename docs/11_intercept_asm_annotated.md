# intercept() annotated disassembly

Source: libxyass.so @ 0x23e54, size 2682 B

String table: 92 decrypted strings

```
023e54  push    {r4, r5, r6, r7, lr}
023e56  add     r7, sp, #0xc
023e58  push.w  {r8, sb, sl, fp}
023e5c  sub     sp, #4
023e5e  vpush   {d8, d9, d10, d11, d12, d13}
023e62  sub     sp, #0xf0
023e64  mov     r5, r0
023e66  ldr     r0, [pc, #0x378]                   ; literal@0x241e0 = 0x00059c68 (+367720)
023e68  ldr     r6, [pc, #0x378]                   ; literal@0x241e4 = 0x0005a096 (+368790)
023e6a  mov     r4, r2
023e6c  add     r0, pc                             ; r0 = 0x7dad8
023e6e  add     r6, pc                             ; r6 = .bss[0x7df08] (cached jmethodID/jfieldID)
023e70  ldr     r1, [r0]
023e72  ldr     r0, [r6]
023e74  str     r1, [sp, #0x18]
023e76  ldr     r1, [r1]
023e78  str     r1, [sp, #0xec]
023e7a  cbnz    r0, #0x23eac
023e7c  movs    r0, #0x50
023e7e  bl      #0xd7a4                            ; → malloc
023e82  vmov.i32 q8, #0
023e86  add.w   r1, r0, #0x10
023e8a  mov     r2, r0
023e8c  str     r0, [r6]
023e8e  vst1.32 {d16, d17}, [r1]
023e92  add.w   r1, r0, #0x20
023e96  vst1.32 {d16, d17}, [r1]
023e9a  add.w   r1, r0, #0x30
023e9e  vst1.32 {d16, d17}, [r1]
023ea2  movs    r1, #0x40
023ea4  vst1.32 {d16, d17}, [r2], r1
023ea8  vst1.32 {d16, d17}, [r2]
023eac  ldr     r1, [r0, #0x30]
023eae  movs    r3, #5
023eb0  str     r1, [sp, #0x64]
023eb2  ldr     r1, [r0, #0x40]
023eb4  ldr     r2, [r0, #0x4c]
023eb6  mov     r0, r5
023eb8  str     r6, [sp, #0x40]
023eba  bl      #0x1ee70                           ; → decrypt_helper2
023ebe  ldr     r0, [r5]
023ec0  ldr.w   r1, [r0, #0x390]
023ec4  mov     r0, r5
023ec6  blx     r1
023ec8  cmp     r0, #1
023eca  bne     #0x23edc
023ecc  ldr     r0, [r5]
023ece  ldr     r1, [r0, #0x40]
023ed0  mov     r0, r5
023ed2  blx     r1
023ed4  ldr     r0, [r5]
023ed6  ldr     r1, [r0, #0x44]
023ed8  mov     r0, r5
023eda  blx     r1
023edc  ldr     r6, [pc, #0x308]                   ; literal@0x241e8 = 0x0005822c (+361004)
023ede  movw    fp, #0x913c
023ee2  ldr     r0, [pc, #0x308]                   ; literal@0x241ec = 0x0005a0d4 (+368852)
023ee4  movt    fp, #0x1058
023ee8  add     r6, pc                             ; r6 = 0x7c118
023eea  str     r4, [sp, #0x20]
023eec  add     r0, pc                             ; r0 = .bss[0x7dfc4] (cached jmethodID/jfieldID)
023eee  ldr     r1, [r6]
023ef0  ldr     r2, [r0]
023ef2  mov     r0, r5
023ef4  add.w   r3, r1, fp
023ef8  mov     r1, r4
023efa  blx     r3
023efc  mov     sb, r0
023efe  ldr     r0, [pc, #0x2f0]                   ; literal@0x241f0 = 0x0005a0c2 (+368834)
023f00  ldr     r1, [r6]
023f02  add     r0, pc                             ; r0 = .bss[0x7dfc8] (cached jmethodID/jfieldID)
023f04  add.w   r3, r1, fp
023f08  mov     r1, sb
023f0a  ldr     r2, [r0]
023f0c  mov     r0, r5
023f0e  blx     r3
023f10  mov     r4, r0
023f12  ldr     r0, [pc, #0x2e0]                   ; literal@0x241f4 = 0x0005a0b2 (+368818)
023f14  ldr     r1, [r6]
023f16  add     r0, pc                             ; r0 = .bss[0x7dfcc] (cached jmethodID/jfieldID)
023f18  add.w   r3, r1, fp
023f1c  mov     r1, r4
023f1e  ldr     r2, [r0]
023f20  mov     r0, r5
023f22  blx     r3
023f24  mov     sl, r0
023f26  ldr     r0, [r6]
023f28  mov     r1, r4
023f2a  add.w   r3, r0, fp
023f2e  ldr     r0, [pc, #0x2c8]                   ; literal@0x241f8 = 0x0005a09c (+368796)
023f30  add     r0, pc                             ; r0 = .bss[0x7dfd0] (cached jmethodID/jfieldID)
023f32  ldr     r2, [r0]
023f34  mov     r0, r5
023f36  blx     r3
023f38  mov     r8, r0
023f3a  ldr     r0, [r6]
023f3c  mov     r1, sb
023f3e  add.w   r3, r0, fp
023f42  ldr     r0, [pc, #0x2b8]                   ; literal@0x241fc = 0x0005a060 (+368736)
023f44  add     r0, pc                             ; r0 = .bss[0x7dfa8] (cached jmethodID/jfieldID)
023f46  ldr     r2, [r0]
023f48  mov     r0, r5
023f4a  blx     r3
023f4c  str     r0, [sp, #0x24]
023f4e  mov     r1, sb
023f50  ldr     r0, [r6]
023f52  add.w   r3, r0, fp
023f56  ldr     r0, [pc, #0x2a8]                   ; literal@0x24200 = 0x0005a074 (+368756)
023f58  str.w   sb, [sp, #0x1c]
023f5c  add     r0, pc                             ; r0 = .bss[0x7dfd4] (cached jmethodID/jfieldID)
023f5e  ldr     r2, [r0]
023f60  mov     r0, r5
023f62  blx     r3
023f64  str     r0, [sp, #0x34]
023f66  ldr     r0, [r6, #4]
023f68  str     r6, [sp, #0x2c]
023f6a  add.w   r3, r0, fp
023f6e  ldr     r0, [pc, #0x294]                   ; literal@0x24204 = 0x0005a062 (+368738)
023f70  ldr     r1, [sp, #0x64]
023f72  add     r0, pc                             ; r0 = .bss[0x7dfd8] (cached jmethodID/jfieldID)
023f74  ldr     r2, [r0]
023f76  mov     r0, r5
023f78  blx     r3
023f7a  str     r0, [sp, #0x58]
023f7c  mov     r1, sl
023f7e  ldr     r0, [r5]
023f80  movs    r2, #0
023f82  str     r5, [sp, #0x5c]
023f84  ldr.w   r3, [r0, #0x2a4]
023f88  mov     r0, r5
023f8a  blx     r3
023f8c  mov     sb, r0
023f8e  blx     #0x766a0                           ; → pthread_cond_wait@plt
023f92  cmn.w   r0, #0x10
023f96  bhs.w   #0x248d8
023f9a  mov     r6, r0
023f9c  cmp     r0, #0xb
023f9e  bhs     #0x23fb0
023fa0  lsls    r0, r6, #1
023fa2  strb.w  r0, [sp, #0x8c]
023fa6  add     r0, sp, #0x8c
023fa8  add.w   r5, r0, #1
023fac  cbnz    r6, #0x23fc8
023fae  b       #0x23fd2
023fb0  add.w   r0, r6, #0x10
023fb4  bic     r4, r0, #0xf
023fb8  mov     r0, r4
023fba  bl      #0xd7a4                            ; → malloc
023fbe  mov     r5, r0
023fc0  strd    r6, r0, [sp, #0x90]
023fc4  adds    r0, r4, #1
023fc6  str     r0, [sp, #0x8c]
023fc8  mov     r0, r5
023fca  mov     r1, sb
023fcc  mov     r2, r6
023fce  blx     #0x174c8                           ; → unknown_helper_174c8
023fd2  ldr.w   fp, [sp, #0x5c]
023fd6  movs    r0, #0
023fd8  strb    r0, [r5, r6]
023fda  ldr.w   r0, [fp]
023fde  ldr.w   r3, [r0, #0x2a8]
023fe2  mov     r0, fp
023fe4  mov     r1, sl
023fe6  mov     r2, sb
023fe8  blx     r3
023fea  ldr     r1, [pc, #0x21c]                   ; literal@0x24208 = 0x00059fea (+368618)
023fec  ldr     r0, [pc, #0x21c]                   ; literal@0x2420c = 0x00059fea (+368618)
023fee  add     r1, pc                             ; r1 = .bss[0x7dfdc] (cached jmethodID/jfieldID)
023ff0  str     r1, [sp, #0x4c]
023ff2  add     r0, pc                             ; r0 = .bss[0x7dfe0] (cached jmethodID/jfieldID)
023ff4  str     r0, [sp, #0x50]
023ff6  ldr     r2, [r1]
023ff8  ldr     r0, [r0]
023ffa  ldr     r1, [sp, #0x58]
023ffc  mov     r3, sl
023ffe  str     r0, [sp]
024000  mov     r0, fp
024002  bl      #0x1edf8                           ; → decrypt_helper
024006  cmp.w   r8, #0
02400a  beq     #0x24020
02400c  ldr     r0, [sp, #0x4c]
02400e  ldr     r2, [r0]
024010  ldr     r0, [sp, #0x50]
024012  ldr     r0, [r0]
024014  ldr     r1, [sp, #0x58]
024016  mov     r3, r8
024018  str     r0, [sp]
02401a  mov     r0, fp
02401c  bl      #0x1edf8                           ; → decrypt_helper
024020  ldr     r0, [pc, #0x1ec]                   ; literal@0x24210 = 0x00059fbe (+368574)
024022  add     r0, pc                             ; r0 = .bss[0x7dfe4] (cached jmethodID/jfieldID)
024024  ldr     r2, [r0]
024026  ldr.w   r8, [sp, #0x34]
02402a  mov     r0, fp
02402c  mov     r1, r8
02402e  bl      #0x1ee34                           ; → string_utility
024032  mov     sl, r0
024034  movs    r0, #0
024036  strd    r0, r0, [sp, #0x84]
02403a  add     r0, sp, #0x80
02403c  adds    r0, #4
02403e  str     r0, [sp, #0x44]
024040  str     r0, [sp, #0x80]
024042  cmp.w   sl, #1
024046  ldr     r0, [pc, #0x1cc]                   ; literal@0x24214 = 0x000580dc (+360668)
024048  add     r0, pc                             ; r0 = 0x7c128
02404a  str     r0, [sp, #0x38]
02404c  blt.w   #0x24308
024050  add     r0, sp, #0x98
024052  movs    r5, #0
024054  add.w   sb, r0, #1
024058  ldr     r0, [pc, #0x1bc]                   ; literal@0x24218 = 0x00059f8a (+368522)
02405a  add     r0, pc                             ; r0 = .bss[0x7dfe8] (cached jmethodID/jfieldID)
02405c  str     r0, [sp, #0x48]
02405e  ldr     r0, [pc, #0x1bc]                   ; literal@0x2421c = 0x00059f54 (+368468)
024060  str.w   sl, [sp, #0x3c]
024064  add     r0, pc                             ; r0 = .bss[0x7dfbc] (cached jmethodID/jfieldID)
024066  str     r0, [sp, #0x14]
024068  str.w   sb, [sp, #0x28]
02406c  ldr     r0, [sp, #0x48]
02406e  ldr     r2, [r0]
024070  mov     r0, fp
024072  mov     r1, r8
024074  mov     r3, r5
024076  bl      #0x1edf8                           ; → decrypt_helper
02407a  mov     r1, r0
02407c  ldr.w   r0, [fp]
024080  ldr.w   r3, [r0, #0x2a4]
024084  mov     r0, fp
024086  movs    r2, #0
024088  str     r1, [sp, #0x64]
02408a  blx     r3
02408c  mov     r6, r0
02408e  movs    r0, #0
024090  str     r0, [sp, #0x74]
024092  mov     r0, r6
024094  blx     #0x766a0                           ; → pthread_cond_wait@plt
024098  cmp     r0, #4
02409a  blo.w   #0x2429c
02409e  str     r5, [sp, #0x54]
0240a0  movw    r4, #0x9d70
0240a4  ldr     r5, [sp, #0x38]
0240a6  movt    r4, #0x9e6
0240aa  ldrb    r0, [r6, #2]
0240ac  ldrh    r2, [r6]
0240ae  ldr     r1, [r5]
0240b0  str     r6, [sp, #0x60]
0240b2  strb.w  r0, [sp, #0x76]
0240b6  strh.w  r2, [sp, #0x74]
0240ba  ldrb    r0, [r1, r4]
0240bc  dmb     ish
0240c0  lsls    r0, r0, #0x1f
0240c2  beq.w   #0x242c4
0240c6  ldr     r0, [r5, #4]
0240c8  ldr     r1, [r0, r4]
0240ca  add     r0, sp, #0x74
0240cc  blx     #0x767a0                           ; → pthread_key_delete@plt
0240d0  ldr.w   sl, [sp, #0x3c]
0240d4  cmp     r0, #0
0240d6  ldr     r5, [sp, #0x54]
0240d8  ldr     r6, [sp, #0x60]
0240da  bne.w   #0x2429c
0240de  ldr     r0, [pc, #0x140]                   ; literal@0x24220 = 0x00059f08 (+368392)
0240e0  add     r0, pc                             ; r0 = .bss[0x7dfec] (cached jmethodID/jfieldID)
0240e2  ldr     r2, [r0]
0240e4  mov     r0, fp
0240e6  mov     r1, r8
0240e8  mov     r3, r5
0240ea  bl      #0x1edf8                           ; → decrypt_helper
0240ee  mov     r6, r0
0240f0  ldr     r0, [sp, #0x60]
0240f2  blx     #0x766a0                           ; → pthread_cond_wait@plt
0240f6  cmn.w   r0, #0x10
0240fa  bhs.w   #0x248d2
0240fe  mov     r5, r0
024100  cmp     r0, #0xb
024102  bhs     #0x24110
024104  lsls    r0, r5, #1
024106  mov     r4, sb
024108  strb.w  r0, [sp, #0x98]
02410c  cbnz    r5, #0x2412e
02410e  b       #0x24138
024110  add.w   r0, r5, #0x10
024114  bic     r8, r0, #0xf
024118  mov     r0, r8
02411a  bl      #0xd7a4                            ; → malloc
02411e  mov     r4, r0
024120  orr     r0, r8, #1
024124  str     r5, [sp, #0x9c]
024126  str     r0, [sp, #0x98]
024128  str     r4, [sp, #0xa0]
02412a  ldr.w   r8, [sp, #0x34]
02412e  ldr     r1, [sp, #0x60]
024130  mov     r0, r4
024132  mov     r2, r5
024134  blx     #0x174c8                           ; → unknown_helper_174c8
024138  ldr.w   sl, [sp, #0x84]
02413c  movs    r0, #0
02413e  strb    r0, [r4, r5]
024140  cmp.w   sl, #0
024144  beq     #0x241d8
024146  ldrb.w  r0, [sp, #0x98]
02414a  ldrd    r8, r5, [sp, #0x9c]
02414e  str     r6, [sp, #0x30]
024150  ands    r1, r0, #1
024154  itt     eq
024156  moveq   r5, sb
024158  lsreq.w r8, r0, #1
02415c  ldr     r4, [sp, #0x44]
02415e  b       #0x2416c
024160  ldr.w   r0, [sl]
024164  cmp     r0, #0
024166  beq     #0x24224
024168  mov     r4, sl
02416a  mov     sl, r0
02416c  mov     r0, sl
02416e  mov     r6, r8
024170  ldrb    r2, [r0, #0x10]!
024174  ldr.w   sb, [r0, #4]
024178  ands    r1, r2, #1
02417c  it      eq
02417e  lsreq.w sb, r2, #1
024182  cmp     sb, r8
024184  it      lo
024186  movlo   r6, sb
024188  cbz     r6, #0x241aa
02418a  ldr.w   fp, [sl, #0x18]
02418e  cmp     r1, #0
024190  it      eq
024192  addeq.w fp, r0, #1
024196  mov     r0, r5
024198  mov     r1, fp
02419a  mov     r2, r6
02419c  blx     #0x76880                           ; → strncmp@plt
0241a0  cbz     r0, #0x241b0
0241a2  cmp.w   r0, #-1
0241a6  ble     #0x24160
0241a8  b       #0x241b4
0241aa  cmp     r8, sb
0241ac  blo     #0x24160
0241ae  b       #0x241c8
0241b0  cmp     r8, sb
0241b2  blo     #0x24160
0241b4  mov     r0, fp
0241b6  mov     r1, r5
0241b8  mov     r2, r6
0241ba  blx     #0x76880                           ; → strncmp@plt
0241be  cbz     r0, #0x241c8
0241c0  cmp.w   r0, #-1
0241c4  ble     #0x241cc
0241c6  b       #0x24226
0241c8  cmp     sb, r8
0241ca  bhs     #0x24226
0241cc  mov     r4, sl
0241ce  ldr     r0, [r4, #4]!
0241d2  cbz     r0, #0x24226
0241d4  mov     sl, r4
0241d6  b       #0x24168
0241d8  ldr     r4, [sp, #0x44]
0241da  mov     sl, r4
0241dc  b       #0x24232
0241de  nop     
0241e0  ldr     r4, [sp, #0x1a0]
0241e2  movs    r5, r0
0241e4  adr     r0, #0x258
0241e6  movs    r5, r0
0241e8  strh    r4, [r5, #0x10]
0241ea  movs    r5, r0
0241ec  adr     r0, #0x350
0241ee  movs    r5, r0
0241f0  adr     r0, #0x308
0241f2  movs    r5, r0
0241f4  adr     r0, #0x2c8
0241f6  movs    r5, r0
0241f8  adr     r0, #0x270
0241fa  movs    r5, r0
0241fc  adr     r0, #0x180
0241fe  movs    r5, r0
024200  adr     r0, #0x1d0
024202  movs    r5, r0
024204  adr     r0, #0x188
024206  movs    r5, r0
024208  ldr     r7, [sp, #0x3a8]
02420a  movs    r5, r0
02420c  ldr     r7, [sp, #0x3a8]
02420e  movs    r5, r0
024210  ldr     r7, [sp, #0x2f8]
024212  movs    r5, r0
024214  strh    r4, [r3, #6]
024216  movs    r5, r0
024218  ldr     r7, [sp, #0x228]
02421a  movs    r5, r0
02421c  ldr     r7, [sp, #0x150]
02421e  movs    r5, r0
024220  ldr     r7, [sp, #0x20]
024222  movs    r5, r0
024224  mov     r4, sl
024226  ldr.w   fp, [sp, #0x5c]
02422a  ldr.w   sb, [sp, #0x28]
02422e  ldrd    r6, r8, [sp, #0x30]
024232  ldr     r5, [r4]
024234  cbnz    r5, #0x24284
024236  movs    r0, #0x20
024238  bl      #0xd7a4                            ; → malloc
02423c  mov     r5, r0
02423e  vldr    d16, [sp, #0x98]
024242  ldr     r0, [sp, #0xa0]
024244  movw    r3, #0x913c
024248  str     r0, [r5, #0x18]
02424a  movs    r0, #0
02424c  str     r0, [r5, #0x1c]
02424e  movt    r3, #0x1058
024252  strd    r0, r0, [r5]
024256  str.w   sl, [r5, #8]
02425a  vstr    d16, [r5, #0x10]
02425e  strd    r0, r0, [sp, #0x98]
024262  str     r0, [sp, #0xa0]
024264  str     r5, [r4]
024266  ldr     r0, [sp, #0x80]
024268  ldr     r0, [r0]
02426a  cmp     r0, #0
02426c  itte    ne
02426e  strne   r0, [sp, #0x80]
024270  ldrne   r1, [r4]
024272  moveq   r1, r5
024274  ldr     r0, [sp, #0x2c]
024276  ldr     r2, [r0, #8]
024278  ldr     r0, [sp, #0x84]
02427a  add     r2, r3
02427c  blx     r2
02427e  ldr     r0, [sp, #0x88]
024280  adds    r0, #1
024282  str     r0, [sp, #0x88]
024284  ldrb.w  r0, [sp, #0x98]
024288  str     r6, [r5, #0x1c]
02428a  lsls    r0, r0, #0x1f
02428c  itt     ne
02428e  ldrne   r0, [sp, #0xa0]
024290  blne    #0xd7f4
024294  ldr.w   sl, [sp, #0x3c]
024298  ldr     r5, [sp, #0x54]
02429a  ldr     r6, [sp, #0x60]
02429c  ldr.w   r0, [fp]
0242a0  ldr.w   r3, [r0, #0x2a8]
0242a4  ldr     r4, [sp, #0x64]
0242a6  mov     r0, fp
0242a8  mov     r2, r6
0242aa  mov     r1, r4
0242ac  blx     r3
0242ae  ldr.w   r0, [fp]
0242b2  ldr     r2, [r0, #0x5c]
0242b4  mov     r0, fp
0242b6  mov     r1, r4
0242b8  blx     r2
0242ba  adds    r5, #1
0242bc  cmp     r5, sl
0242be  bne.w   #0x2406c
0242c2  b       #0x24308
0242c4  ldr     r0, [sp, #0x14]
0242c6  bl      #0xdff0                            ; → helper_dff0
0242ca  cmp     r0, #0
0242cc  beq.w   #0x240c6
0242d0  movs    r0, #4
0242d2  bl      #0xd7f0                            ; → calloc_like
0242d6  mov     r6, r0
0242d8  movw    r0, #0x512e
0242dc  movt    r0, #3
0242e0  movs    r1, #4
0242e2  str     r0, [r6]
0242e4  mov     r0, r6
0242e6  bl      #0x1a170                           ; → decrypt_fn_A
0242ea  ldr     r5, [sp, #0x38]
0242ec  movw    r4, #0x9d70
0242f0  movt    r4, #0x9e6
0242f4  ldr     r0, [r5, #4]
0242f6  str     r6, [r0, r4]
0242f8  ldr     r0, [sp, #0x14]
0242fa  bl      #0xe0c8                            ; → helper_e0c8
0242fe  ldr.w   fp, [sp, #0x5c]
024302  ldr.w   r8, [sp, #0x34]
024306  b       #0x240c6
024308  ldr     r6, [sp, #0x38]
02430a  movw    r4, #0x9d70
02430e  movt    r4, #0x9e6
024312  ldr     r0, [r6, #8]
024314  ldrb    r0, [r0, r4]
024316  dmb     ish
02431a  lsls    r0, r0, #0x1f
02431c  beq.w   #0x248de
024320  ldr     r0, [r6, #0xc]
024322  ldr.w   r8, [r0, r4]
024326  mov     r0, r8
024328  blx     #0x766a0                           ; → pthread_cond_wait@plt
02432c  cmn.w   r0, #0x10
024330  bhs.w   #0x24926
024334  mov     r5, r0
024336  cmp     r0, #0xb
024338  bhs     #0x2434a
02433a  lsls    r0, r5, #1
02433c  strb.w  r0, [sp, #0x74]
024340  add     r0, sp, #0x74
024342  add.w   r6, r0, #1
024346  cbnz    r5, #0x24364
024348  b       #0x2436e
02434a  add.w   r0, r5, #0x10
02434e  bic     r4, r0, #0xf
024352  mov     r0, r4
024354  bl      #0xd7a4                            ; → malloc
024358  mov     r6, r0
02435a  orr     r0, r4, #1
02435e  str     r5, [sp, #0x78]
024360  str     r0, [sp, #0x74]
024362  str     r6, [sp, #0x7c]
024364  mov     r0, r6
024366  mov     r1, r8
024368  mov     r2, r5
02436a  blx     #0x174c8                           ; → unknown_helper_174c8
02436e  movs    r0, #0
024370  strb    r0, [r6, r5]
024372  ldrb.w  r0, [sp, #0x74]
024376  lsls    r1, r0, #0x1f
024378  bne     #0x24384
02437a  add     r1, sp, #0x74
02437c  adds    r6, r1, #1
02437e  add.w   r1, r6, r0, lsr #1
024382  b       #0x2438a
024384  ldrd    r0, r6, [sp, #0x78]
024388  adds    r1, r6, r0
02438a  ldr     r4, [sp, #0x5c]
02438c  cmp     r6, r1
02438e  beq     #0x2441a
024390  subs    r2, r1, r6
024392  cmp     r2, #0x10
024394  blo     #0x24404
024396  bic     r5, r2, #0xf
02439a  vmvn.i32 q8, #0x60
02439e  vmov.i32 q9, #0x1a
0243a2  mov     r0, r6
0243a4  vmov.i8 q10, #0x20
0243a8  mov     r3, r5
0243aa  vld1.8  {d22, d23}, [r0]
0243ae  subs    r3, #0x10
0243b0  vmovl.u8 q12, d23
0243b4  vmovl.u8 q13, d22
0243b8  vaddw.u16 q14, q8, d25
0243bc  vaddw.u16 q15, q8, d27
0243c0  vaddw.u16 q12, q8, d24
0243c4  vaddw.u16 q13, q8, d26
0243c8  vcgt.u32 q14, q9, q14
0243cc  vcgt.u32 q12, q9, q12
0243d0  vcgt.u32 q15, q9, q15
0243d4  vcgt.u32 q13, q9, q13
0243d8  vmovn.i32 d29, q14
0243dc  vmovn.i32 d28, q12
0243e0  vmovn.i32 d25, q15
0243e4  vmovn.i32 d24, q13
0243e8  vmovn.i16 d29, q14
0243ec  veor    q13, q11, q10
0243f0  vmovn.i16 d28, q12
0243f4  vbit    q11, q13, q14
0243f8  vst1.8  {d22, d23}, [r0]!
0243fc  bne     #0x243aa
0243fe  cmp     r5, r2
024400  beq     #0x2441a
024402  add     r6, r5
024404  ldrb    r0, [r6]
024406  sub.w   r2, r0, #0x61
02440a  cmp     r2, #0x1a
02440c  it      lo
02440e  eorlo   r0, r0, #0x20
024412  strb    r0, [r6], #1
024416  cmp     r1, r6
024418  bne     #0x24404
02441a  ldr     r0, [sp, #0x88]
02441c  cmp     r0, #0
02441e  ldr     r0, [pc, #0x1e4]                   ; literal@0x24604 = 0x00059bcc (+367564)
024420  add     r0, pc                             ; r0 = .bss[0x7dff0] (cached jmethodID/jfieldID)
024422  str     r0, [sp, #0x64]
024424  beq.w   #0x24608
024428  ldr     r5, [sp, #0x80]
02442a  ldr     r0, [sp, #0x44]
02442c  ldr     r6, [sp, #0x40]
02442e  cmp     r5, r0
024430  beq.w   #0x245ec
024434  add.w   sb, sp, #0x98
024438  vmvn.i32 q4, #0x60
02443c  vmov.i32 q5, #0x1a
024440  add.w   sl, sb, #1
024444  vmov.i8 q6, #0x20
024448  mov.w   fp, #0
02444c  b       #0x24456
02444e  ldr     r0, [sp, #0x44]
024450  cmp     r5, r0
024452  beq.w   #0x245e6
024456  add.w   r1, r5, #0x10
02445a  mov     r0, sb
02445c  bl      #0xd9a8                            ; → helper_d9a8
024460  ldrb.w  r0, [sp, #0x98]
024464  ands    lr, r0, #1
024468  bne     #0x24478
02446a  add.w   r1, sb, r0, lsr #1
02446e  mov     r2, sl
024470  adds    r1, #1
024472  cmp     r2, r1
024474  bne     #0x24482
024476  b       #0x24508
024478  ldrd    r1, r2, [sp, #0x9c]
02447c  add     r1, r2
02447e  cmp     r2, r1
024480  beq     #0x24508
024482  subs    r4, r1, r2
024484  cmp     r4, #0x10
024486  blo     #0x244ea
024488  bic     ip, r4, #0xf
02448c  mov     r6, r2
02448e  mov     r3, ip
024490  vld1.8  {d16, d17}, [r6]
024494  subs    r3, #0x10
024496  vmovl.u8 q9, d17
02449a  vmovl.u8 q10, d16
02449e  vaddw.u16 q11, q4, d19
0244a2  vaddw.u16 q12, q4, d21
0244a6  vaddw.u16 q9, q4, d18
0244aa  vaddw.u16 q10, q4, d20
0244ae  vcgt.u32 q11, q5, q11
0244b2  vcgt.u32 q9, q5, q9
0244b6  vcgt.u32 q12, q5, q12
0244ba  vcgt.u32 q10, q5, q10
0244be  vmovn.i32 d23, q11
0244c2  vmovn.i32 d22, q9
0244c6  vmovn.i32 d19, q12
0244ca  vmovn.i32 d18, q10
0244ce  vmovn.i16 d23, q11
0244d2  veor    q10, q8, q6
0244d6  vmovn.i16 d22, q9
0244da  vbit    q8, q10, q11
0244de  vst1.8  {d16, d17}, [r6]!
0244e2  bne     #0x24490
0244e4  cmp     ip, r4
0244e6  beq     #0x24508
0244e8  add     r2, ip
0244ea  ldrb    r0, [r2]
0244ec  sub.w   r3, r0, #0x61
0244f0  cmp     r3, #0x1a
0244f2  it      lo
0244f4  eorlo   r0, r0, #0x20
0244f8  strb    r0, [r2], #1
0244fc  cmp     r1, r2
0244fe  bne     #0x244ea
024500  ldrb.w  r0, [sp, #0x98]
024504  and     lr, r0, #1
024508  ldrb.w  r1, [sp, #0x74]
02450c  cmp.w   lr, #0
024510  ldr     r4, [sp, #0x9c]
024512  ldr.w   r8, [sp, #0x78]
024516  ldr     r6, [r5, #0x1c]
024518  it      eq
02451a  lsreq   r4, r0, #1
02451c  ands    r3, r1, #1
024520  it      eq
024522  lsreq.w r8, r1, #1
024526  cmp     r4, r8
024528  mov     r2, r8
02452a  it      lo
02452c  movlo   r2, r4
02452e  cbz     r2, #0x2454a
024530  cmp     r3, #0
024532  ldr     r0, [sp, #0x7c]
024534  ldr     r1, [sp, #0xa0]
024536  add     r3, sp, #0x74
024538  it      eq
02453a  addeq   r0, r3, #1
02453c  cmp.w   lr, #0
024540  it      eq
024542  moveq   r1, sl
024544  blx     #0x76880                           ; → strncmp@plt
024548  cbnz    r0, #0x2455a
02454a  movs    r0, #0
02454c  cmp     r4, r8
02454e  it      lo
024550  movlo   r0, #1
024552  cmp     r8, r4
024554  it      lo
024556  movlo.w r0, #-1
02455a  cmp.w   r0, #-1
02455e  mov.w   r0, #0
024562  it      gt
024564  movgt   r0, #1
024566  ldr     r4, [sp, #0x5c]
024568  orr.w   r0, r0, fp
02456c  lsls    r0, r0, #0x1f
02456e  bne     #0x2458a
024570  ldr     r0, [sp, #0x64]
024572  ldr     r3, [r0]
024574  ldr     r0, [sp, #0x4c]
024576  ldr     r2, [r0]
024578  ldr     r0, [sp, #0x50]
02457a  ldr     r0, [r0]
02457c  ldr     r1, [sp, #0x58]
02457e  str     r0, [sp]
024580  mov     r0, r4
024582  bl      #0x1edf8                           ; → decrypt_helper
024586  mov.w   fp, #1
02458a  ldr     r0, [sp, #0x4c]
02458c  ldr     r2, [r0]
02458e  ldr     r0, [sp, #0x50]
024590  ldr     r0, [r0]
024592  ldr     r1, [sp, #0x58]
024594  mov     r3, r6
024596  str     r0, [sp]
024598  mov     r0, r4
02459a  bl      #0x1edf8                           ; → decrypt_helper
02459e  ldr     r0, [r4]
0245a0  ldr     r2, [r0, #0x5c]
0245a2  mov     r0, r4
0245a4  mov     r1, r6
0245a6  blx     r2
0245a8  ldrb.w  r0, [sp, #0x98]
0245ac  lsls    r0, r0, #0x1f
0245ae  itt     ne
0245b0  ldrne   r0, [sp, #0xa0]
0245b2  blne    #0xd7f4
0245b6  ldr     r0, [r5, #4]
0245b8  ldr     r6, [sp, #0x40]
0245ba  cbz     r0, #0x245c6
0245bc  mov     r5, r0
0245be  ldr     r0, [r0]
0245c0  cmp     r0, #0
0245c2  bne     #0x245bc
0245c4  b       #0x2444e
0245c6  mov     r0, r5
0245c8  ldr     r1, [r0, #8]!
0245cc  ldr     r2, [r1]
0245ce  cmp     r2, r5
0245d0  mov     r5, r1
0245d2  beq.w   #0x2444e
0245d6  ldr     r1, [r0]
0245d8  mov     r0, r1
0245da  ldr     r5, [r0, #8]!
0245de  ldr     r2, [r5]
0245e0  cmp     r2, r1
0245e2  bne     #0x245d6
0245e4  b       #0x2444e
0245e6  lsls.w  r0, fp, #0x1f
0245ea  bne     #0x2461e
0245ec  ldr     r0, [sp, #0x64]
0245ee  ldr     r3, [r0]
0245f0  ldr     r0, [sp, #0x4c]
0245f2  ldr     r2, [r0]
0245f4  ldr     r0, [sp, #0x50]
0245f6  ldr     r0, [r0]
0245f8  ldr     r1, [sp, #0x58]
0245fa  str     r0, [sp]
0245fc  mov     r0, r4
0245fe  bl      #0x1edf8                           ; → decrypt_helper
024602  b       #0x2461e
024604  ldr     r3, [sp, #0x330]
024606  movs    r5, r0
024608  ldr     r3, [r0]
02460a  ldr     r0, [sp, #0x4c]
02460c  ldr     r2, [r0]
02460e  ldr     r0, [sp, #0x50]
024610  ldr     r0, [r0]
024612  ldr     r1, [sp, #0x58]
024614  str     r0, [sp]
024616  mov     r0, r4
024618  bl      #0x1edf8                           ; → decrypt_helper
02461c  ldr     r6, [sp, #0x40]
02461e  ldr     r0, [sp, #0x24]
024620  cbz     r0, #0x24632
024622  ldr     r0, [pc, #0x398]                   ; literal@0x249bc = 0x000599cc (+367052)
024624  add     r0, pc                             ; r0 = .bss[0x7dff4] (cached jmethodID/jfieldID)
024626  ldr     r2, [r0]
024628  ldr     r1, [sp, #0x24]
02462a  mov     r0, r4
02462c  ldr     r3, [sp, #0x58]
02462e  bl      #0x26714                           ; → sub_26714
024632  ldr     r0, [r6]
024634  cbnz    r0, #0x24666
024636  movs    r0, #0x50
024638  bl      #0xd7a4                            ; → malloc
02463c  vmov.i32 q8, #0
024640  movs    r1, #0x40
024642  mov     r2, r0
024644  str     r0, [r6]
024646  vst1.32 {d16, d17}, [r2], r1
02464a  add.w   r1, r0, #0x30
02464e  vst1.32 {d16, d17}, [r1]
024652  add.w   r1, r0, #0x20
024656  vst1.32 {d16, d17}, [r1]
02465a  add.w   r1, r0, #0x10
02465e  vst1.32 {d16, d17}, [r2]
024662  vst1.32 {d16, d17}, [r1]
024666  ldr     r1, [r0, #0x40]
024668  ldr     r2, [r0, #0x4c]
02466a  mov     r0, r4
02466c  movs    r3, #6
02466e  bl      #0x1ee70                           ; → decrypt_helper2
024672  ldr     r0, [r4]
024674  ldr.w   r1, [r0, #0x390]
024678  mov     r0, r4
02467a  blx     r1
02467c  cmp     r0, #1
02467e  bne     #0x24690
024680  ldr     r0, [r4]
024682  ldr     r1, [r0, #0x40]
024684  mov     r0, r4
024686  blx     r1
024688  ldr     r0, [r4]
02468a  ldr     r1, [r0, #0x44]
02468c  mov     r0, r4
02468e  blx     r1
024690  add     r1, sp, #0x98
024692  vmov.i32 q8, #0
024696  movs    r0, #0x40
024698  ldr.w   sl, [r7, #8]
02469c  mov     r2, r1
02469e  vst1.64 {d16, d17}, [r2], r0
0246a2  add.w   r0, r1, #0x30
0246a6  add.w   r5, sl, #0x1c
0246aa  vst1.64 {d16, d17}, [r0]
0246ae  add.w   r0, r1, #0x20
0246b2  vst1.64 {d16, d17}, [r0]
0246b6  add.w   r0, r1, #0x10
0246ba  vst1.64 {d16, d17}, [r2]
0246be  vst1.64 {d16, d17}, [r0]
0246c2  mov     r0, r5
0246c4  blx     #0x76890                           ; → strncmp@plt
0246c8  ldr.w   r0, [sl, #0x18]
0246cc  add.w   r8, sp, #0x8c
0246d0  add     r1, sp, #0x98
0246d2  mov     r2, r8
0246d4  bl      #0x26c6c                           ; → sub_26c6c
0246d8  mov     r0, r5
0246da  blx     #0x768a0                           ; → strncmp@plt
0246de  ldr     r0, [r6]
0246e0  cbnz    r0, #0x24712
0246e2  movs    r0, #0x50
0246e4  bl      #0xd7a4                            ; → malloc
0246e8  vmov.i32 q8, #0
0246ec  movs    r1, #0x40
0246ee  mov     r2, r0
0246f0  str     r0, [r6]
0246f2  vst1.32 {d16, d17}, [r2], r1
0246f6  add.w   r1, r0, #0x30
0246fa  vst1.32 {d16, d17}, [r1]
0246fe  add.w   r1, r0, #0x20
024702  vst1.32 {d16, d17}, [r1]
024706  add.w   r1, r0, #0x10
02470a  vst1.32 {d16, d17}, [r2]
02470e  vst1.32 {d16, d17}, [r1]
024712  ldr     r1, [r0, #0x40]
024714  ldr     r2, [r0, #0x4c]
024716  ldr     r0, [sp, #0x5c]
024718  movs    r3, #7
02471a  bl      #0x1ee70                           ; → decrypt_helper2
02471e  ldr     r0, [sp, #0x5c]
024720  ldr     r1, [r0]
024722  ldr.w   r1, [r1, #0x390]
024726  blx     r1
024728  cmp     r0, #1
02472a  bne     #0x2473c
02472c  ldr     r0, [sp, #0x5c]
02472e  ldr     r1, [r0]
024730  ldr     r1, [r1, #0x40]
024732  blx     r1
024734  ldr     r0, [sp, #0x5c]
024736  ldr     r1, [r0]
024738  ldr     r1, [r1, #0x44]
02473a  blx     r1
02473c  ldr     r4, [sp, #0x5c]
02473e  add     r5, sp, #0x68
024740  add.w   sb, sp, #0x98
024744  ldr     r2, [sp, #0x58]
024746  mov     r0, r5
024748  mov     r1, r4
02474a  mov     r3, sb
02474c  bl      #0x24a1c                           ; → sub_24a1c
024750  ldr     r0, [r4]
024752  ldrb.w  r2, [sp, #0x68]
024756  ldr     r1, [sp, #0x70]
024758  ldr.w   r3, [r0, #0x29c]
02475c  lsls    r0, r2, #0x1f
02475e  it      eq
024760  addeq   r1, r5, #1
024762  mov     r0, r4
024764  blx     r3
024766  mov     fp, r0
024768  ldr     r0, [r6]
02476a  cbnz    r0, #0x2479c
02476c  movs    r0, #0x50
02476e  bl      #0xd7a4                            ; → malloc
024772  vmov.i32 q8, #0
024776  movs    r1, #0x40
024778  mov     r2, r0
02477a  str     r0, [r6]
02477c  vst1.32 {d16, d17}, [r2], r1
024780  add.w   r1, r0, #0x30
024784  vst1.32 {d16, d17}, [r1]
024788  add.w   r1, r0, #0x20
02478c  vst1.32 {d16, d17}, [r1]
024790  add.w   r1, r0, #0x10
024794  vst1.32 {d16, d17}, [r2]
024798  vst1.32 {d16, d17}, [r1]
02479c  ldr     r1, [r0, #0x40]
02479e  ldr     r2, [r0, #0x4c]
0247a0  ldr     r0, [sp, #0x5c]
0247a2  movs    r3, #8
0247a4  bl      #0x1ee70                           ; → decrypt_helper2
0247a8  ldr     r0, [sp, #0x5c]
0247aa  ldr     r1, [r0]
0247ac  ldr.w   r1, [r1, #0x390]
0247b0  blx     r1
0247b2  cmp     r0, #1
0247b4  bne     #0x247c6
0247b6  ldr     r0, [sp, #0x5c]
0247b8  ldr     r1, [r0]
0247ba  ldr     r1, [r1, #0x40]
0247bc  blx     r1
0247be  ldr     r0, [sp, #0x5c]
0247c0  ldr     r1, [r0]
0247c2  ldr     r1, [r1, #0x44]
0247c4  blx     r1
0247c6  ldr     r0, [pc, #0x234]                   ; literal@0x249fc = 0x0005982c (+366636)
0247c8  add     r0, pc                             ; r0 = .bss[0x7dff8] (cached jmethodID/jfieldID)
0247ca  ldr     r2, [r0]
0247cc  ldr     r5, [sp, #0x5c]
0247ce  ldr     r1, [sp, #0x1c]
0247d0  mov     r0, r5
0247d2  bl      #0x1edf8                           ; → decrypt_helper
0247d6  mov     r6, r0
0247d8  ldr     r0, [pc, #0x224]                   ; literal@0x24a00 = 0x000597a8 (+366504)
0247da  ldr     r4, [pc, #0x228]                   ; literal@0x24a04 = 0x000597a2 (+366498)
0247dc  add     r0, pc                             ; r0 = .bss[0x7df88] (cached jmethodID/jfieldID)
0247de  add     r4, pc                             ; r4 = .bss[0x7df84] (cached jmethodID/jfieldID)
0247e0  ldr     r3, [r0]
0247e2  ldr     r2, [r4]
0247e4  mov     r0, r5
0247e6  mov     r1, r6
0247e8  str.w   fp, [sp]
0247ec  bl      #0x1edf8                           ; → decrypt_helper
0247f0  ldr     r0, [pc, #0x214]                   ; literal@0x24a08 = 0x00059804 (+366596)
0247f2  ldr     r2, [r4]
0247f4  add     r0, pc                             ; r0 = .bss[0x7dffc] (cached jmethodID/jfieldID)
0247f6  ldr     r3, [r0]
0247f8  ldr     r0, [sp, #0x64]
0247fa  ldr     r0, [r0]
0247fc  str     r0, [sp]
0247fe  mov     r0, r5
024800  mov     r1, r6
024802  bl      #0x1edf8                           ; → decrypt_helper
024806  ldr     r0, [pc, #0x204]                   ; literal@0x24a0c = 0x00059780 (+366464)
024808  add     r0, pc                             ; r0 = .bss[0x7df8c] (cached jmethodID/jfieldID)
02480a  ldr     r2, [r0]
02480c  mov     r0, r5
02480e  mov     r1, r6
024810  bl      #0x1edf8                           ; → decrypt_helper
024814  mov     r3, r0
024816  ldr     r0, [pc, #0x1f8]                   ; literal@0x24a10 = 0x00059778 (+366456)
024818  add     r0, pc                             ; r0 = .bss[0x7df94] (cached jmethodID/jfieldID)
02481a  ldr     r2, [r0]
02481c  ldr     r1, [sp, #0x20]
02481e  mov     r0, r5
024820  bl      #0x1edf8                           ; → decrypt_helper
024824  mov     r4, r0
024826  ldr     r0, [r5]
024828  ldr.w   r1, [r0, #0x390]
02482c  mov     r0, r5
02482e  blx     r1
024830  cbz     r0, #0x24836
024832  movs    r5, #0
024834  b       #0x24866
024836  ldr     r0, [pc, #0x1dc]                   ; literal@0x24a14 = 0x00059724 (+366372)
024838  add     r0, pc                             ; r0 = .bss[0x7df60] (cached jmethodID/jfieldID)
02483a  ldr     r3, [r0]
02483c  str     r6, [sp]
02483e  mov     r1, r4
024840  ldr     r6, [sp, #0x5c]
024842  ldr     r2, [sp, #0x58]
024844  ldr     r0, [sp, #0x20]
024846  strd    r0, sl, [sp, #4]
02484a  mov     r0, r6
02484c  strd    sb, r8, [sp, #0xc]
024850  bl      #0x250f4                           ; → sub_250f4
024854  mov     r5, r0
024856  ldr     r0, [r6]
024858  ldr.w   r1, [r0, #0x390]
02485c  mov     r0, r6
02485e  blx     r1
024860  cmp     r0, #0
024862  it      ne
024864  movne   r5, #0
024866  ldrb.w  r0, [sp, #0x68]
02486a  lsls    r0, r0, #0x1f
02486c  itt     ne
02486e  ldrne   r0, [sp, #0x70]
024870  blne    #0xd7f4
024874  ldrb.w  r0, [sp, #0xdc]
024878  lsls    r0, r0, #0x1f
02487a  itt     ne
02487c  ldrne   r0, [sp, #0xe4]
02487e  blne    #0xd7f4
024882  ldrb.w  r0, [sp, #0x74]
024886  lsls    r0, r0, #0x1f
024888  itt     ne
02488a  ldrne   r0, [sp, #0x7c]
02488c  blne    #0xd7f4
024890  ldr     r0, [sp, #0x2c]
024892  movw    r2, #0x913c
024896  ldr     r1, [sp, #0x84]
024898  movt    r2, #0x1058
02489c  ldr     r0, [r0, #0xc]
02489e  add     r2, r0
0248a0  add     r0, sp, #0x80
0248a2  blx     r2
0248a4  ldrb.w  r0, [sp, #0x8c]
0248a8  lsls    r0, r0, #0x1f
0248aa  itt     ne
0248ac  ldrne   r0, [sp, #0x94]
0248ae  blne    #0xd7f4
0248b2  ldr     r0, [sp, #0xec]
0248b4  ldr     r1, [sp, #0x18]
0248b6  ldr     r1, [r1]
0248b8  cmp     r1, r0
0248ba  itttt   eq
0248bc  moveq   r0, r5
0248be  addeq   sp, #0xf0
0248c0  vpopeq  {d8, d9, d10, d11, d12, d13}
0248c4  addeq   sp, #4
0248c6  itt     eq
0248c8  popeq.w {r8, sb, sl, fp}
0248cc  popeq   {r4, r5, r6, r7, pc}
```