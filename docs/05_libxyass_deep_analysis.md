# libxyass.so — Deep Ghidra Analysis

Script: `scratch/ghidra_work/DeepAnalyze.java`

## 1. MD5 primitive xrefs

MD5 IV @ `0x0002ad60` is referenced by 0 functions:


## 2. String decryptor search

Looking for constant `0x666e4b10` used as function-pointer adjustment.

Found `0x666e4b10` literal used in 0 instructions across 0 functions.


## 3. RegisterNatives analysis

JNI_OnLoad @ `0002ef68` — scanning for RegisterNatives call...

- Potential RegisterNatives reference @ `0002f0e6`: `ldr.w r5,[r2,#0x35c]`

## 4. Encrypted string blob scan

- `destroy` found @ `0001079a` (plaintext)

## 5. XOR-loop candidate functions (potential string decryptors)


Total XOR-loop candidate functions: 0

## 6. Largest functions in libxyass

- `00020a88` FUN_00020a88 — 4514 bytes
- `00085adc` FUN_00085adc — 2458 bytes
- `000386d0` FUN_000386d0 — 2108 bytes
- `0008520c` FUN_0008520c — 1950 bytes
- `00024074` FUN_00024074 — 1662 bytes
- `0001ee44` FUN_0001ee44 — 1596 bytes
- `00021f24` FUN_00021f24 — 1324 bytes
- `0001e868` FUN_0001e868 — 1286 bytes
- `0002808c` FUN_0002808c — 1172 bytes
- `0002ef68` JNI_OnLoad — 1068 bytes
- `00027a9c` FUN_00027a9c — 1000 bytes
- `0001f654` FUN_0001f654 — 896 bytes
- `000350f4` FUN_000350f4 — 820 bytes
- `00027510` FUN_00027510 — 784 bytes
- `00034bcc` FUN_00034bcc — 674 bytes

## 7. Top-5 decompiled functions (looking for signing glue)

### top-1 — FUN_00020a88 @ `00020a88` (4514 bytes)

```c

void FUN_00020a88(int *param_1)

{
  byte bVar1;
  undefined1 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  char *pcVar9;
  int *piVar10;
  int iVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  byte *pbVar14;
  char *pcVar15;
  int iVar16;
  byte *pbVar17;
  undefined *puVar18;
  int iVar19;
  uint uVar20;
  int iVar21;
  int iVar22;
  int iVar23;
  int iVar24;
  bool bVar25;
  int *piVar26;
  byte *pbVar27;
  undefined1 local_58;
  int local_48;
  undefined1 uStack_39;
  int *local_38;
  undefined4 uStack_34;
  int *local_30;
  int iStack_2c;
  int local_28;
  
  piVar26 = *(int **)(DAT_00020dec + 0x20a9a);
  local_28 = *piVar26;
  iVar24 = DAT_00020df0 + 0x20aaa;
  iVar22 = DAT_00020df0 + 0x20aac;
  uStack_39 = FUN_0001e800(param_1,iVar24,iVar22);
  iVar23 = DAT_00020e08;
  iVar21 = DAT_00020e04;
  iVar19 = DAT_00020e00;
  iVar16 = DAT_00020dfc;
  iVar8 = DAT_00020df8;
  iVar11 = DAT_00020df4;
  pbVar27 = (byte *)*param_1;
  pbVar14 = (byte *)param_1[1];
  if ((uint)((int)pbVar14 - (int)pbVar27) < 2) goto switchD_00020c6e_caseD_6e;
  uVar20 = (uint)*pbVar27;
  if (0x28 < uVar20 - 0x4c) {
    if (uVar20 - 0x31 < 9) {
      FUN_00022650(param_1);
      goto switchD_00020c6e_caseD_6e;
    }
switchD_00020afc_caseD_4d:
    iVar11 = FUN_0001e800(param_1,DAT_00020e0c + 0x20b7a,DAT_00020e0c + 0x20b85);
    if (iVar11 == 0) {
      iVar11 = FUN_0001e800(param_1,DAT_00021300 + 0x210ac,DAT_00021300 + 0x210b7);
      if ((iVar11 != 0) && (local_30 = (int *)FUN_00020a88(param_1), local_30 != (int *)0x0)) {
        FUN_00022a30(param_1,&local_30);
      }
    }
    else {
      local_30 = (int *)FUN_0001ee44(param_1);
      if (local_30 != (int *)0x0) {
        FUN_00022a30(param_1,&local_30);
      }
    }
    goto switchD_00020c6e_caseD_6e;
  }
  local_48 = DAT_00020df4 + 0x20ae0;
  iVar3 = DAT_00020df8 + 0x20ae6;
  iVar4 = DAT_00020dfc + 0x20aec;
  iVar5 = DAT_00020e00 + 0x20af2;
  iVar6 = DAT_00020e04 + 0x20af8;
  iVar7 = DAT_00020e08 + 0x20afe;
  switch(uVar20) {
  case 0x4c:
    FUN_00021f24(param_1);
    break;
  default:
    goto switchD_00020afc_caseD_4d;
  case 0x54:
    FUN_0002032c(param_1);
    break;
  case 0x61:
    bVar1 = pbVar27[1];
    if (bVar1 != 0x4e) {
      if (bVar1 == 0x53) {
        *param_1 = (int)(pbVar27 + 2);
        puVar18 = (undefined *)(iVar21 + 0x20af9);
      }
      else {
        if (bVar1 == 0x7a) {
          *param_1 = (int)(pbVar27 + 2);
          local_30 = (int *)FUN_00020a88(param_1);
LAB_00021650:
          if (local_30 != (int *)0x0) {
            FUN_00021ee0(param_1,DAT_00021738 + 0x21662,&local_30);
          }
          break;
        }
        if (bVar1 == 100) {
          *param_1 = (int)(pbVar27 + 2);
          iVar19 = iVar19 + 0x20af3;
          goto LAB_000218b0;
        }
        if (bVar1 == 0x6e) {
          *param_1 = (int)(pbVar27 + 2);
          puVar18 = (undefined *)(iVar19 + 0x20af3);
          iVar6 = iVar5;
        }
        else {
          if (bVar1 == 0x74) {
            *param_1 = (int)(pbVar27 + 2);
            local_30 = (int *)FUN_0001ee44(param_1);
            goto LAB_00021650;
          }
          if (bVar1 != 0x61) break;
          *param_1 = (int)(pbVar27 + 2);
          puVar18 = (undefined *)(iVar16 + 0x20aee);
          iVar6 = iVar4;
        }
      }
      goto LAB_000218c4;
    }
    iVar11 = (int)&switchD_00020afc::switchdataD_00020b00 + DAT_00020e08;
    *param_1 = (int)(pbVar27 + 2);
    goto LAB_0002147e;
  case 99:
    bVar1 = pbVar27[1];
    if (bVar1 == 0x76) {
      iVar11 = FUN_0001e800(param_1,DAT_000216ec + 0x21354,DAT_000216ec + 0x21356);
      if (iVar11 != 0) {
        iVar11 = param_1[0x61];
        *(undefined1 *)(param_1 + 0x61) = 0;
        iVar8 = FUN_0001ee44(param_1);
        *(char *)(param_1 + 0x61) = (char)iVar11;
        if (iVar8 != 0) {
          pcVar15 = (char *)*param_1;
          pcVar9 = (char *)param_1[1];
          if ((pcVar15 == pcVar9) || (*pcVar15 != '_')) {
            iVar11 = FUN_00020a88(param_1);
            if (iVar11 != 0) {
              piVar10 = (int *)FUN_0001fd44(param_1 + 0x66,4);
              *piVar10 = iVar11;
              uVar12 = FUN_0001fd44(param_1 + 0x66,0x14);
              iStack_2c = 1;
LAB_00021b02:
              FUN_00023c4c(uVar12,iVar8,piVar10,iStack_2c);
            }
          }
          else {
            iVar16 = param_1[3];
            iVar11 = param_1[2];
            pcVar15 = pcVar15 + 1;
            *param_1 = (int)pcVar15;
            while( true ) {
              if ((pcVar15 != pcVar9) && (*pcVar15 == 'E')) {
                *param_1 = (int)(pcVar15 + 1);
                FUN_0001fbb6(&local_30,param_1,iVar16 - iVar11 >> 2);
                uVar12 = FUN_0001fd44(param_1 + 0x66,0x14);
                piVar10 = local_30;
                goto LAB_00021b02;
              }
              local_30 = (int *)FUN_00020a88(param_1);
              if (local_30 == (int *)0x0) break;
              FUN_0001fb3c(param_1 + 2,&local_30);
              pcVar15 = (char *)*param_1;
              pcVar9 = (char *)param_1[1];
            }
          }
        }
      }
      break;
    }
    if (bVar1 == 0x6c) {
      *param_1 = (int)(pbVar27 + 2);
      iVar11 = FUN_00020a88(param_1);
      if (iVar11 != 0) {
        iVar8 = param_1[2];
        iVar16 = param_1[3];
        while ((pcVar9 = (char *)*param_1, pcVar9 == (char *)param_1[1] || (*pcVar9 != 'E'))) {
          local_30 = (int *)FUN_00020a88(param_1);
          if (local_30 == (int *)0x0) goto switchD_00020c6e_caseD_6e;
          FUN_0001fb3c(param_1 + 2,&local_30);
        }
        *param_1 = (int)(pcVar9 + 1);
        FUN_0001fbb6(&local_30,param_1,iVar16 - iVar8 >> 2);
        piVar10 = (int *)FUN_0001fd44(param_1 + 0x66,0x14);
        piVar10[1] = DAT_00021b68;
        piVar10[2] = iVar11;
        *piVar10 = DAT_00021b6c + 0x219c2;
        piVar10[3] = (int)local_30;
        piVar10[4] = iStack_2c;
      }
      break;
    }
    if (bVar1 != 0x6d) {
      if (bVar1 != 0x6f) {
        if (bVar1 != 99) break;
        *param_1 = (int)(pbVar27 + 2);
        iVar11 = FUN_0001ee44(param_1);
        if ((iVar11 == 0) || (iVar8 = FUN_00020a88(param_1), iVar8 == 0)) break;
        piVar10 = (int *)FUN_0001fd44(param_1 + 0x66,0x18);
        iVar19 = DAT_00020e28 + 0x20d1c;
        iVar21 = DAT_00020e28 + 0x20d26;
        iVar16 = DAT_00020e2c;
LAB_00021882:
        *piVar10 = DAT_00021b4c + 0x21890;
        piVar10[1] = iVar16;
        piVar10[2] = iVar19;
        piVar10[3] = iVar21;
        piVar10[4] = iVar11;
        piVar10[5] = iVar8;
        break;
      }
      *param_1 = (int)(pbVar27 + 2);
      iVar5 = DAT_0002133c + 0x2129c;
LAB_000218ac:
      iVar19 = iVar5 + 1;
      goto LAB_000218b0;
    }
    *param_1 = (int)(pbVar27 + 2);
    puVar18 = (undefined *)(iVar8 + 0x20ae7);
    iVar6 = iVar3;
    goto LAB_000218c4;
  case 100:
    bVar1 = pbVar27[1];
    switch(bVar1) {
    case 0x6c:
      *param_1 = (int)(pbVar27 + 2);
      local_30 = (int *)FUN_00020a88(param_1);
      if (local_30 == (int *)0x0) break;
      local_38 = (int *)((uint)local_38 & 0xffffff00);
      goto LAB_0002110e;
    case 0x6d:
    case 0x6f:
    case 0x70:
    case 0x71:
    case 0x72:
    case 0x75:
      break;
    case 0x6e:
      goto LAB_00021828;
    case 0x73:
      *param_1 = (int)(pbVar27 + 2);
      local_30 = (int *)FUN_00020a88(param_1);
      if ((local_30 == (int *)0x0) ||
         (local_38 = (int *)FUN_00020a88(param_1), local_38 == (int *)0x0)) break;
      iVar11 = DAT_00021b30 + 0x217c2;
LAB_000217c0:
      FUN_000227dc(param_1,&local_30,iVar11,&local_38);
      break;
    case 0x74:
      *param_1 = (int)(pbVar27 + 2);
      iVar11 = FUN_00020a88(param_1);
      if ((iVar11 != 0) && (iVar8 = FUN_00020a88(param_1), iVar8 != 0)) {
        piVar10 = (int *)FUN_0001fd44(param_1 + 0x66,0x18);
        iVar16 = DAT_00021b3c;
        iVar19 = DAT_00021b34 + 0x21804;
        iVar21 = DAT_00021b34 + 0x21805;
        iVar23 = 
// ... [truncated]

```

### top-2 — FUN_00085adc @ `00085adc` (2458 bytes)

```c

void FUN_00085adc(undefined4 *param_1,int *param_2)

{
  undefined2 uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined8 *puVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  int *piVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  undefined8 uVar14;
  
  iVar2 = DAT_00085ec4;
  piVar9 = *(int **)(DAT_00085ec0 + 0x85af4);
  iVar6 = *piVar9;
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(DAT_00085ec4 + 0x85af8) + 0x6f8d925c) & 1) == 0) &&
     (iVar8 = FUN_0001dff0(DAT_00085ec8 + 0x85e74), iVar8 != 0)) {
    puVar4 = (undefined8 *)FUN_0001d7f0(0x18);
    iVar8 = *(int *)(iVar2 + 0x85afc);
    uVar10 = *(undefined8 *)(iVar8 + 0x6f8d9264);
    uVar11 = *(undefined8 *)(iVar8 + 0x6f8d926c);
    iVar5 = *(int *)(DAT_00085ecc + 0x85e92);
    *puVar4 = *(undefined8 *)(iVar8 + 0x6f8d925c);
    puVar4[1] = uVar10;
    puVar4[2] = uVar11;
    (*(code *)(iVar5 + -0x6906f920))(puVar4,0x18);
    iVar8 = DAT_00085ed0 + 0x85eb8;
    *(undefined8 **)(*(int *)(iVar2 + 0x85b00) + 0x6f8d925c) = puVar4;
    FUN_0001e0c8(iVar8);
  }
  uVar3 = (**(code **)(*param_2 + 0x18))
                    (param_2,*(undefined4 *)(*(int *)(iVar2 + 0x85b00) + 0x6f8d925c));
  uVar3 = (**(code **)(*param_2 + 0x54))(param_2,uVar3);
  *param_1 = uVar3;
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar2 + 0x85b04) + 0x6f8d925c) & 1) == 0) &&
     (iVar8 = FUN_0001dff0(DAT_00086264 + 0x85eda), iVar8 != 0)) {
    puVar4 = (undefined8 *)FUN_0001d7f0(0x11);
    iVar8 = DAT_00086268;
    iVar5 = *(int *)(iVar2 + 0x85b08);
    uVar10 = *(undefined8 *)(iVar5 + 0x6f8d9264);
    *puVar4 = *(undefined8 *)(iVar5 + 0x6f8d925c);
    puVar4[1] = uVar10;
    iVar8 = *(int *)(iVar8 + 0x85efe);
    *(undefined1 *)(puVar4 + 2) = *(undefined1 *)(iVar5 + 0x6f8d926c);
    (*(code *)(iVar8 + -0x6906f920))(puVar4,0x11);
    iVar8 = DAT_0008626c + 0x85f1a;
    *(undefined8 **)(*(int *)(iVar2 + 0x85b0c) + 0x6f8d925c) = puVar4;
    FUN_0001e0c8(iVar8);
  }
  uVar3 = (**(code **)(*param_2 + 0x18))
                    (param_2,*(undefined4 *)(*(int *)(iVar2 + 0x85b0c) + 0x6f8d925c));
  uVar3 = (**(code **)(*param_2 + 0x54))(param_2,uVar3);
  param_1[1] = uVar3;
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar2 + 0x85b10) + 0x6f8d925c) & 1) == 0) &&
     (iVar8 = FUN_0001dff0(DAT_00086270 + 0x85f28), iVar8 != 0)) {
    puVar4 = (undefined8 *)FUN_0001d7f0(0x22);
    iVar8 = *(int *)(iVar2 + 0x85b14);
    uVar10 = *(undefined8 *)(iVar8 + 0x6f8d925c);
    uVar11 = *(undefined8 *)(iVar8 + 0x6f8d9264);
    piVar7 = (int *)(DAT_00086274 + 0x85f4c);
    uVar12 = *(undefined8 *)(iVar8 + 0x6f8d9274);
    uVar1 = *(undefined2 *)(iVar8 + 0x6f8d927c);
    puVar4[2] = *(undefined8 *)(iVar8 + 0x6f8d926c);
    puVar4[3] = uVar12;
    *puVar4 = uVar10;
    puVar4[1] = uVar11;
    iVar8 = *piVar7;
    *(undefined2 *)(puVar4 + 4) = uVar1;
    (*(code *)(iVar8 + -0x6906f920))(puVar4,0x22);
    iVar8 = DAT_00086278 + 0x85f7a;
    *(undefined8 **)(*(int *)(iVar2 + 0x85b18) + 0x6f8d925c) = puVar4;
    FUN_0001e0c8(iVar8);
  }
  uVar3 = (**(code **)(*param_2 + 0x18))
                    (param_2,*(undefined4 *)(*(int *)(iVar2 + 0x85b18) + 0x6f8d925c));
  uVar3 = (**(code **)(*param_2 + 0x54))(param_2,uVar3);
  param_1[2] = uVar3;
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar2 + 0x85b1c) + 0x6f8d925c) & 1) == 0) &&
     (iVar8 = FUN_0001dff0(DAT_0008627c + 0x85f88), iVar8 != 0)) {
    puVar4 = (undefined8 *)FUN_0001d7f0(0x29);
    iVar8 = *(int *)(iVar2 + 0x85b20);
    uVar10 = *(undefined8 *)(iVar8 + 0x6f8d925c);
    uVar11 = *(undefined8 *)(iVar8 + 0x6f8d9264);
    uVar12 = *(undefined8 *)(iVar8 + 0x6f8d9275);
    uVar13 = *(undefined8 *)(iVar8 + 0x6f8d927d);
    iVar5 = *(int *)(DAT_00086280 + 0x85fac);
    uVar14 = *(undefined8 *)(iVar8 + 0x6f8d9274);
    puVar4[2] = *(undefined8 *)(iVar8 + 0x6f8d926c);
    puVar4[3] = uVar14;
    *puVar4 = uVar10;
    puVar4[1] = uVar11;
    *(undefined8 *)((int)puVar4 + 0x19) = uVar12;
    *(undefined8 *)((int)puVar4 + 0x21) = uVar13;
    (*(code *)(iVar5 + -0x6906f920))(puVar4,0x29);
    iVar8 = DAT_00086284 + 0x85fde;
    *(undefined8 **)(*(int *)(iVar2 + 0x85b24) + 0x6f8d925c) = puVar4;
    FUN_0001e0c8(iVar8);
  }
  uVar3 = (**(code **)(*param_2 + 0x18))
                    (param_2,*(undefined4 *)(*(int *)(iVar2 + 0x85b24) + 0x6f8d925c));
  uVar3 = (**(code **)(*param_2 + 0x54))(param_2,uVar3);
  param_1[3] = uVar3;
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar2 + 0x85b28) + 0x6f8d925c) & 1) == 0) &&
     (iVar8 = FUN_0001dff0(DAT_00086288 + 0x85fec), iVar8 != 0)) {
    puVar4 = (undefined8 *)FUN_0001d7f0(0x22);
    iVar8 = *(int *)(iVar2 + 0x85b2c);
    uVar10 = *(undefined8 *)(iVar8 + 0x6f8d925c);
    uVar11 = *(undefined8 *)(iVar8 + 0x6f8d9264);
    piVar7 = (int *)(DAT_0008628c + 0x86010);
    uVar12 = *(undefined8 *)(iVar8 + 0x6f8d9274);
    uVar1 = *(undefined2 *)(iVar8 + 0x6f8d927c);
    puVar4[2] = *(undefined8 *)(iVar8 + 0x6f8d926c);
    puVar4[3] = uVar12;
    *puVar4 = uVar10;
    puVar4[1] = uVar11;
    iVar8 = *piVar7;
    *(undefined2 *)(puVar4 + 4) = uVar1;
    (*(code *)(iVar8 + -0x6906f920))(puVar4,0x22);
    iVar8 = DAT_00086290 + 0x8603e;
    *(undefined8 **)(*(int *)(iVar2 + 0x85b30) + 0x6f8d925c) = puVar4;
    FUN_0001e0c8(iVar8);
  }
  uVar3 = (**(code **)(*param_2 + 0x18))
                    (param_2,*(undefined4 *)(*(int *)(iVar2 + 0x85b30) + 0x6f8d925c));
  uVar3 = (**(code **)(*param_2 + 0x54))(param_2,uVar3);
  param_1[4] = uVar3;
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar2 + 0x85b34) + 0x6f8d925c) & 1) == 0) &&
     (iVar8 = FUN_0001dff0(DAT_00086294 + 0x8604c), iVar8 != 0)) {
    puVar4 = (undefined8 *)FUN_0001d7f0(0x10);
    uVar10 = *(undefined8 *)(*(int *)(iVar2 + 0x85b38) + 0x6f8d9264);
    iVar8 = *(int *)(DAT_00086298 + 0x86072);
    *puVar4 = *(undefined8 *)(*(int *)(iVar2 + 0x85b38) + 0x6f8d925c);
    puVar4[1] = uVar10;
    (*(code *)(iVar8 + -0x6906f920))(puVar4,0x10);
    iVar8 = DAT_0008629c + 0x86086;
    *(undefined8 **)(*(int *)(iVar2 + 0x85b3c) + 0x6f8d925c) = puVar4;
    FUN_0001e0c8(iVar8);
  }
  uVar3 = (**(code **)(*param_2 + 0x18))
                    (param_2,*(undefined4 *)(*(int *)(iVar2 + 0x85b3c) + 0x6f8d925c));
  uVar3 = (**(code **)(*param_2 + 0x54))(param_2,uVar3);
  param_1[5] = uVar3;
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar2 + 0x85b40) + 0x6f8d925c) & 1) == 0) &&
     (iVar8 = FUN_0001dff0(DAT_000862a0 + 0x86094), iVar8 != 0)) {
    puVar4 = (undefined8 *)FUN_0001d7f0(0x10);
    uVar10 = *(undefined8 *)(*(int *)(iVar2 + 0x85b44) + 0x6f8d9264);
    iVar8 = *(int *)(DAT_000862a4 + 0x860ba);
    *puVar4 = *(undefined8 *)(*(int *)(iVar2 + 0x85b44) + 0x6f8d925c);
    puVar4[1] = uVar10;
    (*(code *)(iVar8 + -0x6906f920))(puVar4,0x10);
    iVar8 = DAT_000862a8 + 0x860ce;
    *(undefined8 **)(*(int *)(iVar2 + 0x85b48) + 0x6f8d925c) = puVar4;
    FUN_0001e0c8(iVar8);
  }
  uVar3 = (**(code **)(*param_2 + 0x18))
                    (param_2,*(undefined4 *)(*(int *)(iVar2 + 0x85b48) + 0x6f8d925c));
  uVar3 = (**(code **)(*param_2 + 0x54))(param_2,uVar3);
  param_1[9] = uVar3;
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar2 + 0x85b4c) + 0x6f8d925c) & 1) == 0) &&
     (iVar8 = FUN_0001dff0(DAT_000862ac + 0x860dc), iVar8 != 0)) {
    puVar4 = (undefined8 *)FUN_0001d7f0(0x18);
    iVar8 = *(int *)(iVar2 + 0x85b50);
    uVar10 = *(undefined8 *)(iVar8 + 0x6f8d9264);
    uVar11 = *(undefined8 *)(iVar8 + 0x6f8d926c);
    iVar5 = *(int *)(DAT_000862b0 + 0x860fa);
    *puVar4 = *(undefined8 *)(iVar8 + 0x6f8d925c);
    puVar4[1] = uVar10;
    puVar4[2] = uVar11;
    (*(code *)(iVar5 + -0x6906f920))(puVar4,0x18);
    iVar8 = DAT_000862b4 + 0x86120;
    *(undefined8 **)(*(int *)(iVar2 + 0x85b54) + 0x6f8d925c) = puVar4;
    FUN_0001e0c8(iVar8);
  }
  uVar3 = (**(code **)(*param_2 + 0x18))
                    (param_2,*(undefined4 *)(*(int *)(iVar2 + 0x85b54) + 0x6f8d925c));
  uVar3 = (**(code **)(*param_2 + 0
// ... [truncated]

```

### top-3 — FUN_000386d0 @ `000386d0` (2108 bytes)

```c

void FUN_000386d0(uint *param_1,uint param_2,byte *param_3,uint param_4,int param_5,byte *param_6,
                 void *param_7,uint param_8)

{
  undefined1 auVar1 [16];
  byte bVar2;
  byte bVar3;
  byte bVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong *puVar7;
  void *__dest;
  byte *pbVar8;
  int iVar9;
  uint uVar10;
  byte *pbVar11;
  byte bVar12;
  int *piVar13;
  int iVar14;
  uint uVar15;
  int iVar16;
  int iVar17;
  uint uVar18;
  int iVar19;
  uint uVar20;
  uint uVar21;
  uint *puVar22;
  uint uVar23;
  byte *pbVar24;
  byte *pbVar25;
  bool bVar26;
  undefined1 auVar27 [16];
  undefined1 auVar28 [16];
  undefined4 local_474;
  uint local_470;
  uint *local_46c;
  undefined8 local_468;
  uint *local_460;
  undefined8 local_458;
  byte *local_450;
  undefined8 local_448;
  byte *local_440;
  undefined8 local_438;
  int local_430 [2];
  undefined8 local_428;
  int iStack_2c;
  
  piVar13 = *(int **)(DAT_00038890 + 0x386ea);
  iStack_2c = *piVar13;
  iVar14 = 2;
  if (param_5 == 0) {
    iVar14 = 1;
  }
  bVar12 = *param_3;
  if ((bVar12 & 1) == 0) {
    uVar15 = (uint)(bVar12 >> 1);
  }
  else {
    uVar15 = *(uint *)(param_3 + 4);
  }
  if ((*param_6 & 1) == 0) {
    uVar23 = (uint)(*param_6 >> 1);
  }
  else {
    uVar23 = *(uint *)(param_6 + 4);
  }
  local_460 = (uint *)FUN_0001d7a4(0x20);
  *(undefined1 *)(local_460 + 6) = 0;
  local_460[5] = param_8 << 0x18 | (param_8 >> 8 & 0xff) << 0x10 | (param_8 >> 0x10 & 0xff) << 8 |
                 param_8 >> 0x18;
  local_460[4] = uVar23 << 0x18 | (uVar23 >> 8 & 0xff) << 0x10 | (uVar23 >> 0x10 & 0xff) << 8 |
                 uVar23 >> 0x18;
  local_460[2] = iVar14 << 0x18;
  local_460[3] = uVar15 << 0x18 | (uVar15 >> 8 & 0xff) << 0x10 | (uVar15 >> 0x10 & 0xff) << 8 |
                 uVar15 >> 0x18;
  local_460[1] = param_4 << 0x18 | (param_4 >> 8 & 0xff) << 0x10 | (param_4 >> 0x10 & 0xff) << 8 |
                 param_4 >> 0x18;
  *local_460 = param_2 << 0x18 | (param_2 >> 8 & 0xff) << 0x10 | (param_2 >> 0x10 & 0xff) << 8 |
               param_2 >> 0x18;
  local_468 = 0x1800000021;
  uVar15 = *(uint *)(param_3 + 4);
  pbVar8 = *(byte **)(param_3 + 8);
  if ((bVar12 & 1) == 0) {
    pbVar8 = param_3 + 1;
    uVar15 = (uint)(bVar12 >> 1);
  }
  puVar7 = (ulonglong *)FUN_0001da9c(&local_468,pbVar8,uVar15);
  local_458 = *puVar7;
  local_450 = *(byte **)(puVar7 + 1);
  *(undefined4 *)puVar7 = 0;
  *(undefined4 *)((int)puVar7 + 4) = 0;
  *(undefined4 *)(puVar7 + 1) = 0;
  uVar15 = *(uint *)(param_6 + 4);
  pbVar8 = *(byte **)(param_6 + 8);
  if ((*param_6 & 1) == 0) {
    pbVar8 = param_6 + 1;
    uVar15 = (uint)(*param_6 >> 1);
  }
  puVar7 = (ulonglong *)FUN_0001da9c(&local_458,pbVar8,uVar15);
  local_438 = *puVar7;
  local_430[0] = (int)puVar7[1];
  *(undefined4 *)puVar7 = 0;
  *(undefined4 *)((int)puVar7 + 4) = 0;
  *(undefined4 *)(puVar7 + 1) = 0;
  if (0xffffffef < param_8) {
                    /* WARNING: Subroutine does not return */
    FUN_0001d7f8(&local_474);
  }
  if (param_8 < 0xb) {
    __dest = (void *)((int)&local_474 + 1);
    local_474 = CONCAT31(local_474._1_3_,(char)(param_8 << 1));
    if (param_8 != 0) goto LAB_000387f2;
  }
  else {
    uVar15 = param_8 + 0x10 & 0xfffffff0;
    __dest = (void *)FUN_0001d7a4(uVar15);
    local_474 = uVar15 | 1;
    local_470 = param_8;
    local_46c = __dest;
LAB_000387f2:
    memcpy(__dest,param_7,param_8);
  }
  *(undefined1 *)((int)__dest + param_8) = 0;
  uVar15 = local_470;
  puVar22 = local_46c;
  if ((local_474 & 1) == 0) {
    puVar22 = (uint *)((int)&local_474 + 1);
    uVar15 = local_474 >> 1 & 0x7f;
  }
  puVar7 = (ulonglong *)FUN_0001da9c(&local_438,puVar22,uVar15);
  local_448 = *puVar7;
  local_440 = *(byte **)(puVar7 + 1);
  *(undefined4 *)puVar7 = 0;
  *(undefined4 *)((int)puVar7 + 4) = 0;
  *(undefined4 *)(puVar7 + 1) = 0;
  if ((local_474 & 1) != 0) {
    FUN_0001d7f4(local_46c);
  }
  if ((local_438 & 1) != 0) {
    FUN_0001d7f4(local_430[0]);
  }
  if ((local_458 & 1) != 0) {
    FUN_0001d7f4(local_450);
  }
  if ((local_468 & 1) != 0) {
    FUN_0001d7f4(local_460);
  }
  if ((local_448 & 1) == 0) {
    uVar15 = (uint)((byte)local_448 >> 1);
  }
  else {
    uVar15 = local_448._4_4_;
    if (0xffffffef < local_448._4_4_) {
                    /* WARNING: Subroutine does not return */
      FUN_0001d7f8(&local_458);
    }
  }
  if (uVar15 < 0xb) {
    pbVar8 = (byte *)((int)&local_458 + 1);
    local_458 = CONCAT71(local_458._1_7_,(char)(uVar15 << 1));
    if (uVar15 == 0) goto LAB_000388b6;
  }
  else {
    pbVar8 = (byte *)FUN_0001d7a4(uVar15 + 0x10 & 0xfffffff0);
    local_458 = CONCAT44(uVar15,uVar15 + 0x10) & 0xfffffffffffffff0 | 1;
    local_450 = pbVar8;
  }
  FUN_000274e0(pbVar8,uVar15);
LAB_000388b6:
  uVar5 = local_458;
  auVar1 = SIMDExpandImmediate(0,0,4);
  auVar27._8_8_ = DAT_00038fc8;
  auVar27._0_8_ = DAT_00038fc0;
  pbVar8[uVar15] = 0;
  local_438 = 0;
  iVar16 = *(int *)(DAT_000388d8 + 0x388cc);
  iVar14 = 0;
  do {
    auVar28 = VectorAdd(auVar27,auVar1,4);
    iVar9 = iVar14 + 0x10;
    *(longlong *)((int)local_430 + iVar14) = auVar27._0_8_;
    *(longlong *)((int)&local_428 + iVar14) = auVar27._8_8_;
    iVar14 = iVar9;
    auVar27 = auVar28;
  } while (iVar9 != 0x400);
  iVar16 = iVar16 + 0x5742d150;
  iVar14 = 0;
  uVar23 = 0;
  uVar15 = 0;
  do {
    iVar9 = uVar15 * 4;
    iVar19 = local_430[uVar15];
    uVar23 = (uint)*(byte *)(iVar16 + iVar14) + uVar23 + iVar19;
    uVar18 = uVar23 & 0xff;
    local_430[uVar15] = local_430[uVar18];
    local_430[uVar18] = iVar19;
    iVar17 = local_430[uVar15 + 1];
    iVar19 = 0;
    if (iVar14 != 0xc) {
      iVar19 = iVar14 + 1;
    }
    uVar23 = uVar23 + iVar17 + (uint)*(byte *)(iVar16 + iVar19);
    uVar18 = uVar23 & 0xff;
    local_430[uVar15 + 1] = local_430[uVar18];
    local_430[uVar18] = iVar17;
    iVar17 = *(int *)((int)&local_428 + iVar9);
    iVar14 = 0;
    if (iVar19 != 0xc) {
      iVar14 = iVar19 + 1;
    }
    uVar23 = uVar23 + iVar17 + (uint)*(byte *)(iVar16 + iVar14);
    uVar18 = uVar23 & 0xff;
    *(int *)((int)&local_428 + iVar9) = local_430[uVar18];
    local_430[uVar18] = iVar17;
    iVar19 = 0;
    if (iVar14 != 0xc) {
      iVar19 = iVar14 + 1;
    }
    iVar14 = *(int *)((int)&local_428 + iVar9 + 4);
    uVar23 = uVar23 + iVar14 + (uint)*(byte *)(iVar16 + iVar19) & 0xff;
    *(int *)((int)&local_428 + iVar9 + 4) = local_430[uVar23];
    local_430[uVar23] = iVar14;
    iVar14 = 0;
    if (iVar19 != 0xc) {
      iVar14 = iVar19 + 1;
    }
    bVar26 = uVar15 < 0xfc;
    uVar15 = uVar15 + 4;
  } while (bVar26);
  bVar12 = (byte)local_458;
  pbVar8 = local_450;
  if ((local_458 & 1) == 0) {
    pbVar8 = (byte *)((int)&local_458 + 1);
  }
  bVar26 = (local_448 & 1) == 0;
  pbVar25 = local_440;
  if (bVar26) {
    pbVar25 = (byte *)((int)&local_448 + 1);
  }
  local_438._0_4_ = 0;
  local_438._4_4_ = 0;
  uVar15 = local_448._4_4_;
  if (bVar26) {
    uVar15 = (uint)((byte)local_448 >> 1);
  }
  uVar23 = (uint)local_438;
  uVar18 = local_438._4_4_;
  if (uVar15 >> 3 != 0) {
    uVar21 = uVar15 >> 3;
    pbVar11 = pbVar8;
    pbVar24 = pbVar25;
    do {
      uVar21 = uVar21 - 1;
      uVar20 = uVar23 + 1 & 0xff;
      iVar16 = local_430[uVar20];
      uVar10 = iVar16 + uVar18 & 0xff;
      iVar14 = local_430[uVar10];
      local_430[uVar20] = iVar14;
      local_430[uVar10] = iVar16;
      pbVar25 = pbVar24 + 8;
      pbVar8 = pbVar11 + 8;
      *pbVar11 = *(byte *)(local_430 + (iVar14 + iVar16 & 0xff)) ^ *pbVar24;
      uVar10 = uVar23 + 2 & 0xff;
      iVar14 = local_430[uVar10];
      uVar20 = iVar14 + iVar16 + uVar18;
      uVar18 = uVar20 & 0xff;
      iVar16 = local_430[uVar18];
      local_430[uVar10] = iVar16;
      local_430[uVar18] = iVar14;
      pbVar11[1] = *(byte *)(local_430 + (iVar16 + iVar14 & 0xff)) ^ pbVar24[1];
      uVar18 = uVar23 + 3 & 0xff;
      iVar14 = local_430[uVar18];
      uVar20 = uVar20 + iVar14;
      uVar10 = uVar20 & 0xff;
      iVar16 = local_430[uVar10];
      local_430[uVar18] = iVar16;
// ... [truncated]

```

### top-4 — FUN_0008520c @ `0008520c` (1950 bytes)

```c

void FUN_0008520c(int param_1,int *param_2)

{
  bool bVar1;
  bool bVar2;
  undefined4 uVar3;
  int *piVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  undefined2 *puVar10;
  undefined8 *puVar11;
  undefined8 *puVar12;
  undefined4 *puVar13;
  int *piVar14;
  int iVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  int iVar18;
  undefined4 uVar19;
  undefined4 uVar20;
  undefined8 uVar21;
  undefined8 uVar22;
  undefined8 uVar23;
  undefined8 uVar24;
  time_t tStack_2c;
  int local_28;
  
  iVar6 = DAT_000855cc;
  piVar14 = *(int **)(DAT_000855c8 + 0x85222);
  local_28 = *piVar14;
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(DAT_000855cc + 0x85228) + -0x337affd4) & 1) == 0) &&
     (iVar9 = FUN_0001dff0(DAT_000859f8 + 0x85630), iVar9 != 0)) {
    puVar12 = (undefined8 *)FUN_0001d7f0(0x18);
    uVar21 = *(undefined8 *)(DAT_000859fc + 0x85650);
    uVar22 = *(undefined8 *)(DAT_000859fc + 0x85658);
    *puVar12 = *(undefined8 *)(DAT_000859fc + 0x85648);
    puVar12[1] = uVar21;
    puVar12[2] = uVar22;
    FUN_0002a170(puVar12,0x18);
    iVar9 = DAT_00085a28 + 0x85668;
    *(undefined8 **)(*(int *)(iVar6 + 0x8522c) + -0x337affd4) = puVar12;
    FUN_0001e0c8(iVar9);
  }
  uVar3 = (**(code **)(*param_2 + 0x18))
                    (param_2,*(undefined4 *)(*(int *)(iVar6 + 0x8522c) + -0x337affd4));
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar6 + 0x85230) + -0x337affd4) & 1) == 0) &&
     (iVar9 = FUN_0001dff0(DAT_00085a2c + 0x85676), iVar9 != 0)) {
    puVar12 = (undefined8 *)FUN_0001d7f0(0x12);
    uVar21 = *(undefined8 *)(DAT_00085a30 + 0x85696);
    puVar10 = (undefined2 *)(DAT_00085a30 + 0x8569e);
    *puVar12 = *(undefined8 *)(DAT_00085a30 + 0x8568e);
    puVar12[1] = uVar21;
    *(undefined2 *)(puVar12 + 2) = *puVar10;
    FUN_0002a9fc(puVar12,0x12);
    iVar9 = DAT_00085a34 + 0x856aa;
    *(undefined8 **)(*(int *)(iVar6 + 0x85234) + -0x337affd4) = puVar12;
    FUN_0001e0c8(iVar9);
  }
  uVar19 = *(undefined4 *)(*(int *)(iVar6 + 0x85234) + -0x337affd4);
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar6 + 0x85238) + -0x337affd4) & 1) == 0) &&
     (iVar9 = FUN_0001dff0(DAT_00085a38 + 0x856bc), iVar9 != 0)) {
    puVar12 = (undefined8 *)FUN_0001d7f0(0x26);
    uVar21 = *(undefined8 *)(DAT_00085a3c + 0x856d4);
    uVar22 = *(undefined8 *)(DAT_00085a3c + 0x856dc);
    uVar24 = *(undefined8 *)(DAT_00085a3c + 0x856f2);
    uVar23 = *(undefined8 *)(DAT_00085a3c + 0x856ec);
    puVar12[2] = *(undefined8 *)(DAT_00085a3c + 0x856e4);
    puVar12[3] = uVar23;
    *puVar12 = uVar21;
    puVar12[1] = uVar22;
    *(undefined8 *)((int)puVar12 + 0x1e) = uVar24;
    FUN_0002a9fc(puVar12,0x26);
    iVar9 = DAT_00085a40 + 0x85706;
    *(undefined8 **)(*(int *)(iVar6 + 0x8523c) + -0x337affd4) = puVar12;
    FUN_0001e0c8(iVar9);
  }
  uVar19 = (**(code **)(*param_2 + 0x84))
                     (param_2,uVar3,uVar19,*(undefined4 *)(*(int *)(iVar6 + 0x8523c) + -0x337affd4))
  ;
  iVar9 = DAT_000855d0;
  piVar4 = (int *)(DAT_000855d0 + 0x852a2);
  uVar19 = (*(code *)(*piVar4 + 0x3180488c))(param_2,*(undefined4 *)(param_1 + 0x48),uVar19);
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar6 + 0x85240) + -0x337affd4) & 1) == 0) &&
     (iVar18 = FUN_0001dff0(DAT_00085a44 + 0x85718), iVar18 != 0)) {
    puVar12 = (undefined8 *)FUN_0001d7f0(0x22);
    uVar21 = *(undefined8 *)(DAT_00085a48 + 0x85730);
    uVar22 = *(undefined8 *)(DAT_00085a48 + 0x85738);
    puVar10 = (undefined2 *)(DAT_00085a48 + 0x85750);
    uVar23 = *(undefined8 *)(DAT_00085a48 + 0x85748);
    puVar12[2] = *(undefined8 *)(DAT_00085a48 + 0x85740);
    puVar12[3] = uVar23;
    *puVar12 = uVar21;
    puVar12[1] = uVar22;
    *(undefined2 *)(puVar12 + 4) = *puVar10;
    FUN_0002a170(puVar12,0x22);
    iVar18 = DAT_00085a4c + 0x8575e;
    *(undefined8 **)(*(int *)(iVar6 + 0x85244) + -0x337affd4) = puVar12;
    FUN_0001e0c8(iVar18);
  }
  uVar5 = (**(code **)(*param_2 + 0x18))
                    (param_2,*(undefined4 *)(*(int *)(iVar6 + 0x85244) + -0x337affd4));
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar6 + 0x85248) + -0x337affd4) & 1) == 0) &&
     (iVar18 = FUN_0001dff0(DAT_00085a50 + 0x8576c), iVar18 != 0)) {
    puVar12 = (undefined8 *)FUN_0001d7f0(0xf);
    uVar21 = *(undefined8 *)(DAT_00085a54 + 0x8578b);
    *puVar12 = *(undefined8 *)(DAT_00085a54 + 0x85784);
    *(undefined8 *)((int)puVar12 + 7) = uVar21;
    FUN_0002b29c(puVar12,0xf);
    iVar18 = DAT_00085a58 + 0x857a6;
    *(undefined8 **)(*(int *)(iVar6 + 0x8524c) + -0x337affd4) = puVar12;
    FUN_0001e0c8(iVar18);
  }
  uVar20 = *(undefined4 *)(*(int *)(iVar6 + 0x8524c) + -0x337affd4);
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar6 + 0x85250) + -0x337affd4) & 1) == 0) &&
     (iVar18 = FUN_0001dff0(DAT_00085a5c + 0x857b4), iVar18 != 0)) {
    puVar12 = (undefined8 *)FUN_0001d7f0(0x36);
    iVar18 = DAT_00085a60;
    puVar11 = (undefined8 *)(DAT_00085a60 + 0x857cc);
    uVar23 = *(undefined8 *)(DAT_00085a60 + 0x857dc);
    uVar24 = *(undefined8 *)(DAT_00085a60 + 0x857e4);
    uVar21 = *(undefined8 *)(DAT_00085a60 + 0x857f4);
    puVar12[4] = *(undefined8 *)(DAT_00085a60 + 0x857ec);
    puVar12[5] = uVar21;
    uVar21 = *puVar11;
    uVar22 = *(undefined8 *)(iVar18 + 0x857d4);
    puVar12[2] = uVar23;
    puVar12[3] = uVar24;
    *puVar12 = uVar21;
    puVar12[1] = uVar22;
    *(undefined8 *)((int)puVar12 + 0x2e) = *(undefined8 *)(iVar18 + 0x857fa);
    FUN_0002a170(puVar12,0x36);
    iVar18 = DAT_00085a64 + 0x8580e;
    *(undefined8 **)(*(int *)(iVar6 + 0x85254) + -0x337affd4) = puVar12;
    FUN_0001e0c8(iVar18);
  }
  uVar5 = (**(code **)(*param_2 + 0x84))
                    (param_2,uVar5,uVar20,*(undefined4 *)(*(int *)(iVar6 + 0x85254) + -0x337affd4));
  uVar20 = (*(code *)(*(int *)(iVar9 + 0x852a6) + 0x3180488c))(param_1,param_2);
  uVar5 = (*(code *)(*piVar4 + 0x3180488c))(param_2,uVar19,uVar5,uVar20,0x40);
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar6 + 0x85258) + -0x337affd4) & 1) == 0) &&
     (iVar18 = FUN_0001dff0(DAT_00085a68 + 0x8581c), iVar18 != 0)) {
    puVar12 = (undefined8 *)FUN_0001d7f0(0x1f);
    uVar21 = *(undefined8 *)(DAT_00085a6c + 0x8583c);
    uVar22 = *(undefined8 *)(DAT_00085a6c + 0x85843);
    uVar23 = *(undefined8 *)(DAT_00085a6c + 0x8584b);
    *puVar12 = *(undefined8 *)(DAT_00085a6c + 0x85834);
    puVar12[1] = uVar21;
    *(undefined8 *)((int)puVar12 + 0xf) = uVar22;
    *(undefined8 *)((int)puVar12 + 0x17) = uVar23;
    FUN_0002bc30(puVar12,0x1f);
    iVar18 = DAT_00085a70 + 0x85856;
    *(undefined8 **)(*(int *)(iVar6 + 0x8525c) + -0x337affd4) = puVar12;
    FUN_0001e0c8(iVar18);
  }
  uVar20 = (**(code **)(*param_2 + 0x18))
                     (param_2,*(undefined4 *)(*(int *)(iVar6 + 0x8525c) + -0x337affd4));
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar6 + 0x85260) + -0x337affd4) & 1) == 0) &&
     (iVar18 = FUN_0001dff0(DAT_00085a74 + 0x85864), iVar18 != 0)) {
    puVar12 = (undefined8 *)FUN_0001d7f0(0xb);
    uVar21 = *(undefined8 *)(DAT_00085a78 + 0x8587c);
    *(undefined4 *)((int)puVar12 + 7) = *(undefined4 *)(DAT_00085a78 + 0x85883);
    *puVar12 = uVar21;
    FUN_0002bc30(puVar12,0xb);
    iVar18 = DAT_00085a7c + 0x8589a;
    *(undefined8 **)(*(int *)(iVar6 + 0x85264) + -0x337affd4) = puVar12;
    FUN_0001e0c8(iVar18);
  }
  uVar16 = *(undefined4 *)(*(int *)(iVar6 + 0x85264) + -0x337affd4);
  DataMemoryBarrier(0x1b);
  if (((*(byte *)(*(int *)(iVar6 + 0x85268) + -0x337affd4) & 1) == 0) &&
     (iVar18 = FUN_0001dff0(DAT_00085a80 + 0x858a8), iVar18 != 0)) {
    puVar12 = (undefined8 *)FUN_0001d7f0(0x20);
    uVar21 = *(undefined8 *)(DAT_00085a84 + 0x858ca);
    uVar22 = *(undefined8 *)(DAT_00085a84 + 0x858d2);
    uVar23 = *(undefined8 *)(DAT_00085a84 + 0x858da);
    *puVar12 = *(undefined8 *)(DAT_00085a84 + 0x858c2);
    puVar12[1] = uVar21;
    puVar12[2] = uVar22;
    puVar12[3] = uVar23;
    FUN_0002c440(puVar12,0x20);
    iVar18 = DAT_00085a88 + 0x858e2;
    *(undefin
// ... [truncated]

```

### top-5 — FUN_00024074 @ `00024074` (1662 bytes)

```c

void FUN_00024074(undefined4 *param_1,undefined1 *param_2)

{
  char cVar1;
  undefined1 uVar2;
  int iVar3;
  int iVar4;
  size_t sVar5;
  int *piVar6;
  int iVar7;
  int *piVar8;
  undefined1 *puVar9;
  char *__s;
  uint uVar10;
  int *piVar11;
  
  piVar11 = *(int **)(DAT_000243f8 + 0x24086);
  piVar6 = (int *)*piVar11;
  puVar9 = (undefined1 *)*param_1;
  uVar10 = (int)param_1[1] - (int)puVar9;
  if ((undefined1 *)param_1[1] == puVar9) goto LAB_0002464c;
  piVar8 = (int *)0x0;
  switch(*puVar9) {
  case 0x61:
    if (1 < uVar10) {
      cVar1 = puVar9[1];
      if (cVar1 == 'N') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_00024784 + 0x2459c;
          goto LAB_00024754;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'S') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 != piVar6) goto LAB_0002465e;
        iVar7 = DAT_00024788 + 0x245b0;
        goto LAB_000246fa;
      }
      if (cVar1 == 'n' || cVar1 == 'd') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_000243fc + 0x24106;
          goto LAB_000246fa;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'a') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_00024780 + 0x244c2;
          goto LAB_00024754;
        }
        goto LAB_0002465e;
      }
    }
    break;
  default:
    goto switchD_000240a2_caseD_62;
  case 99:
    if (uVar10 < 2) break;
    cVar1 = puVar9[1];
    piVar8 = (int *)0x0;
    if (cVar1 == 'v') {
      uVar2 = *(undefined1 *)(param_1 + 0x61);
      cVar1 = *(char *)((int)param_1 + 0x185);
      *(undefined1 *)(param_1 + 0x61) = 0;
      *param_1 = puVar9 + 2;
      *(bool *)((int)param_1 + 0x185) = param_2 != (undefined1 *)0x0 || cVar1 != '\0';
      iVar7 = FUN_0001ee44(param_1);
      if (iVar7 == 0) {
        piVar8 = (int *)0x0;
      }
      else {
        if (param_2 != (undefined1 *)0x0) {
          *param_2 = 1;
        }
        piVar8 = (int *)FUN_00024870(param_1,&stack0xffffffd8);
      }
      *(undefined1 *)(param_1 + 0x61) = uVar2;
      *(char *)((int)param_1 + 0x185) = cVar1;
    }
    else {
      if (cVar1 == 'm') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_0002478c + 0x24536;
          goto LAB_000246fa;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'o') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_00024790 + 0x2454c;
          goto LAB_000246fa;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'l') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_00024418 + 0x2426a;
          goto LAB_00024754;
        }
        goto LAB_0002465e;
      }
    }
    goto switchD_000240a2_caseD_62;
  case 100:
    if (1 < uVar10) {
      cVar1 = puVar9[1];
      if (cVar1 == 'V') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_0002479c + 0x245c4;
          goto LAB_00024754;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'v') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_00024798 + 0x245d8;
          goto LAB_000246fa;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'e') {
LAB_000243e2:
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = (int)&DAT_000243f8 + DAT_00024434;
LAB_000246fa:
          FUN_0002484a(param_1,iVar7);
          return;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'l') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          __s = (char *)(DAT_00024794 + 0x245ee);
          piVar6 = (int *)FUN_0001fd44(param_1 + 0x66,0x10);
          sVar5 = strlen(__s);
          iVar3 = DAT_0002080c;
          iVar7 = DAT_00020808;
          piVar6[2] = (int)__s;
          piVar6[3] = (int)(__s + sVar5);
          *piVar6 = iVar3 + 0x20804;
          piVar6[1] = iVar7;
          return;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'a') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          FUN_0002489c(param_1,DAT_00024400 + 0x24144);
          return;
        }
        goto LAB_0002465e;
      }
    }
    break;
  case 0x65:
    if (1 < uVar10) {
      cVar1 = puVar9[1];
      if (cVar1 == 'O') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_000247a0 + 0x24464;
          goto LAB_00024754;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'q') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_000247a4 + 0x2447a;
          goto LAB_00024754;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'o') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_0002441c + 0x2429a;
          goto LAB_000246fa;
        }
        goto LAB_0002465e;
      }
    }
    break;
  case 0x67:
    if (1 < uVar10) {
      if (puVar9[1] == 't') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_00024430 + 0x243e2;
          goto LAB_000246fa;
        }
        goto LAB_0002465e;
      }
      if (puVar9[1] == 'e') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_00024420 + 0x242c4;
          goto LAB_00024754;
        }
        goto LAB_0002465e;
      }
    }
    break;
  case 0x69:
    if ((1 < uVar10) && (puVar9[1] == 'x')) {
      *param_1 = puVar9 + 2;
      piVar8 = (int *)*piVar11;
      if (piVar8 == piVar6) {
        iVar7 = DAT_00024404 + 0x24174;
        goto LAB_00024754;
      }
      goto LAB_0002465e;
    }
    break;
  case 0x6c:
    if (1 < uVar10) {
      cVar1 = puVar9[1];
      if (cVar1 == 'S') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_000247b0 + 0x2460e;
          goto LAB_0002471c;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 't') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DAT_000247b4 + 0x24622;
          goto LAB_000246fa;
        }
        goto LAB_0002465e;
      }
      if (cVar1 == 'i') {
        *param_1 = puVar9 + 2;
        iVar7 = FUN_00023f70(param_1);
        if (iVar7 != 0) {
          piVar8 = (int *)FUN_0001fd44(param_1 + 0x66,0xc);
          iVar4 = DAT_000247a8;
          iVar3 = DAT_0002477c;
          piVar8[2] = iVar7;
          *piVar8 = iVar4 + 0x2464c;
          piVar8[1] = iVar3;
          goto switchD_000240a2_caseD_62;
        }
      }
      else {
        if (cVar1 == 's') {
          *param_1 = puVar9 + 2;
          piVar8 = (int *)*piVar11;
          if (piVar8 == piVar6) {
            iVar7 = DAT_000247ac + 0x24676;
            goto LAB_00024754;
          }
          goto LAB_0002465e;
        }
        if (cVar1 == 'e') {
          *param_1 = puVar9 + 2;
          piVar8 = (int *)*piVar11;
          if (piVar8 == piVar6) {
            iVar7 = DAT_00024424 + 0x24300;
            goto LAB_00024754;
          }
          goto LAB_0002465e;
        }
      }
    }
    break;
  case 0x6d:
    if (1 < uVar10) {
      cVar1 = puVar9[1];
      if (cVar1 == 'I') {
        *param_1 = puVar9 + 2;
        piVar8 = (int *)*piVar11;
        if (piVar8 == piVar6) {
          iVar7 = DA
// ... [truncated]

```

