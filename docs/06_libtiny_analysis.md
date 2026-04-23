# libtiny.so — Ghidra analysis

## Basic info
- Functions: 4232

## JNI exports (Java_com_xingin_*)


Total: 0

## Crypto / signature strings

| Address | String |
|---|---|
| `0001211d` | `pthread_cond_signal` |
| `0006c02e` | `"invalid number; expected digit after exponent sign` |
| `0006ced7` | `"unknown token` |

Total interesting strings: 3

## Functions referencing crypto/signing strings

- `00191ad8` FUN_00191ad8 (sz=3250)
- `001f4594` FUN_001f4594 (sz=3250)

## Top decompiled functions

### FUN_00191ad8 @ `00191ad8` (3250 bytes)

```c

void FUN_00191ad8(int param_1)

{
  byte *pbVar1;
  char cVar2;
  undefined1 uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined1 *puVar6;
  uint uVar7;
  int iVar8;
  int *piVar9;
  char *pcVar10;
  undefined4 extraout_r0;
  uint uVar11;
  undefined4 extraout_r1;
  int *piVar12;
  undefined1 *puVar13;
  ulonglong uVar14;
  longlong lVar15;
  char *local_28;
  int local_24;
  
  piVar12 = *(int **)(DAT_00191d64 + 0x191ae6);
  local_24 = *piVar12;
  if (*(int *)(param_1 + 0x14) == 0) {
    iVar4 = FUN_0019683c(param_1);
    if (iVar4 != 0xef) {
      piVar9 = (int *)(param_1 + 0x18);
      iVar4 = *piVar9;
      *(undefined1 *)(param_1 + 0x10) = 1;
      *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + -1;
      if (iVar4 == 0) {
        piVar9 = (int *)(param_1 + 0x1c);
        iVar4 = *piVar9;
        if (iVar4 != 0) goto LAB_00191b38;
      }
      else {
LAB_00191b38:
        *piVar9 = iVar4 + -1;
      }
      if (*(int *)(param_1 + 0xc) != -1) {
        *(int *)(param_1 + 0x24) = *(int *)(param_1 + 0x24) + -1;
      }
      goto LAB_00191b50;
    }
    iVar4 = FUN_0019683c(param_1);
    if ((iVar4 == 0xbb) && (iVar4 = FUN_0019683c(param_1), iVar4 == 0xbf)) goto LAB_00191b50;
    iVar4 = DAT_00191d68 + 0x191b16;
    goto LAB_00191c10;
  }
LAB_00191b50:
  do {
    FUN_0019683c(param_1);
    iVar4 = *(int *)(param_1 + 0xc);
    if (0x17 < iVar4 - 9U) break;
  } while ((1 << (iVar4 - 9U & 0xff) & 0x800013U) != 0);
  cVar2 = *(char *)(param_1 + 8);
  while ((cVar2 != '\0' && (iVar4 == 0x2f))) {
    iVar4 = FUN_0019683c(param_1);
    if (iVar4 == 0x2a) {
      while( true ) {
        while (iVar4 = FUN_0019683c(param_1), iVar4 != 0x2a) {
          if (iVar4 + 1U < 2) {
            iVar4 = DAT_00191d6c + 0x191c12;
            goto LAB_00191c10;
          }
        }
        iVar4 = FUN_0019683c(param_1);
        if (iVar4 == 0x2f) break;
        iVar4 = *(int *)(param_1 + 0x18);
        *(undefined1 *)(param_1 + 0x10) = 1;
        *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + -1;
        piVar9 = (int *)(param_1 + 0x18);
        if ((iVar4 != 0) ||
           (iVar4 = *(int *)(param_1 + 0x1c), piVar9 = (int *)(param_1 + 0x1c), iVar4 != 0)) {
          *piVar9 = iVar4 + -1;
        }
        if (*(int *)(param_1 + 0xc) != -1) {
          *(int *)(param_1 + 0x24) = *(int *)(param_1 + 0x24) + -1;
        }
      }
    }
    else {
      if (iVar4 != 0x2f) {
        iVar4 = DAT_00192098 + 0x191e16;
        goto LAB_00191c10;
      }
      do {
        do {
          iVar4 = FUN_0019683c(param_1);
        } while (0xe < iVar4 + 1U);
      } while ((0x4803U >> (iVar4 + 1U & 0xff) & 1) == 0);
    }
    do {
      FUN_0019683c(param_1);
      iVar4 = *(int *)(param_1 + 0xc);
      if (0x17 < iVar4 - 9U) break;
    } while ((1 << (iVar4 - 9U & 0xff) & 0x800013U) != 0);
    cVar2 = *(char *)(param_1 + 8);
  }
  uVar5 = 8;
  switch(iVar4) {
  default:
    goto switchD_00191c32_caseD_1;
  case 0x22:
    pbVar1 = (byte *)(param_1 + 0x2c);
    if ((*pbVar1 & 1) == 0) {
      uVar3 = 0x22;
      pbVar1[0] = 0;
      pbVar1[1] = 0;
    }
    else {
      **(undefined1 **)(param_1 + 0x34) = 0;
      uVar3 = (undefined1)*(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x30) = 0;
    }
    puVar13 = *(undefined1 **)(param_1 + 0x20);
    if (puVar13 < *(undefined1 **)(param_1 + 0x28)) {
      *puVar13 = uVar3;
      *(undefined1 **)(param_1 + 0x24) = puVar13 + 1;
    }
    else {
      uVar7 = (int)*(undefined1 **)(param_1 + 0x28) - (int)puVar13;
      iVar4 = uVar7 * 2;
      if (uVar7 == 0) {
        iVar4 = 1;
      }
      if (0x3ffffffe < uVar7) {
        iVar4 = 0x7fffffff;
      }
      puVar6 = (undefined1 *)FUN_0007df6a(iVar4);
      *puVar6 = uVar3;
      *(undefined1 **)(param_1 + 0x28) = puVar6 + iVar4;
      *(undefined1 **)(param_1 + 0x20) = puVar6;
      *(undefined1 **)(param_1 + 0x24) = puVar6 + 1;
      if (puVar13 != (undefined1 *)0x0) {
        free(puVar13);
      }
    }
    iVar4 = DAT_001920a8 + 0x192080;
LAB_0019207e:
    uVar5 = FUN_0019683c(param_1);
    switch(uVar5) {
    case 0:
      iVar8 = DAT_00192a1c + 0x19280e;
      goto switchD_0019253e_caseD_23;
    case 1:
      iVar8 = DAT_0019296c + 0x192814;
      goto switchD_0019253e_caseD_23;
    case 2:
      iVar8 = DAT_00192970 + 0x19281a;
      goto switchD_0019253e_caseD_23;
    case 3:
      iVar8 = DAT_00192974 + 0x192820;
      goto switchD_0019253e_caseD_23;
    case 4:
      iVar8 = DAT_00192978 + 0x192826;
      goto switchD_0019253e_caseD_23;
    case 5:
      iVar8 = DAT_0019297c + 0x19282c;
      goto switchD_0019253e_caseD_23;
    case 6:
      iVar8 = DAT_00192980 + 0x192832;
      goto switchD_0019253e_caseD_23;
    case 7:
      iVar8 = (int)&DAT_00192838 + DAT_00192984;
      goto switchD_0019253e_caseD_23;
    case 8:
      iVar8 = DAT_00192988 + 0x192842;
      goto switchD_0019253e_caseD_23;
    case 9:
      iVar8 = DAT_0019298c + 0x192848;
      goto switchD_0019253e_caseD_23;
    case 10:
      iVar8 = DAT_00192990 + 0x19284e;
      goto switchD_0019253e_caseD_23;
    case 0xb:
      iVar8 = DAT_00192994 + 0x192854;
      goto switchD_0019253e_caseD_23;
    case 0xc:
      iVar8 = DAT_00192998 + 0x19285a;
      goto switchD_0019253e_caseD_23;
    case 0xd:
      iVar8 = DAT_0019299c + 0x192860;
      goto switchD_0019253e_caseD_23;
    case 0xe:
      iVar8 = DAT_001929a0 + 0x192866;
      goto switchD_0019253e_caseD_23;
    case 0xf:
      iVar8 = DAT_001929a4 + 0x19286c;
      goto switchD_0019253e_caseD_23;
    case 0x10:
      iVar8 = DAT_001929a8 + 0x192872;
      goto switchD_0019253e_caseD_23;
    case 0x11:
      iVar8 = DAT_001929ac + 0x192878;
      goto switchD_0019253e_caseD_23;
    case 0x12:
      iVar8 = DAT_001929b0 + 0x19287e;
      goto switchD_0019253e_caseD_23;
    case 0x13:
      iVar8 = DAT_001929b4 + 0x192884;
      goto switchD_0019253e_caseD_23;
    case 0x14:
      iVar8 = DAT_001929b8 + 0x19288a;
      goto switchD_0019253e_caseD_23;
    case 0x15:
 
// ... [truncated]

```

### FUN_001f4594 @ `001f4594` (3250 bytes)

```c

void FUN_001f4594(int param_1)

{
  byte *pbVar1;
  char cVar2;
  undefined1 uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined1 *puVar6;
  uint uVar7;
  int iVar8;
  int *piVar9;
  char *pcVar10;
  undefined4 extraout_r0;
  uint uVar11;
  undefined4 extraout_r1;
  int *piVar12;
  undefined1 *puVar13;
  ulonglong uVar14;
  longlong lVar15;
  char *local_28;
  int local_24;
  
  piVar12 = *(int **)(DAT_001f4820 + 0x1f45a2);
  local_24 = *piVar12;
  if (*(int *)(param_1 + 0x14) == 0) {
    iVar4 = FUN_001f69c8(param_1);
    if (iVar4 != 0xef) {
      piVar9 = (int *)(param_1 + 0x18);
      iVar4 = *piVar9;
      *(undefined1 *)(param_1 + 0x10) = 1;
      *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + -1;
      if (iVar4 == 0) {
        piVar9 = (int *)(param_1 + 0x1c);
        iVar4 = *piVar9;
        if (iVar4 != 0) goto LAB_001f45f4;
      }
      else {
LAB_001f45f4:
        *piVar9 = iVar4 + -1;
      }
      if (*(int *)(param_1 + 0xc) != -1) {
        *(int *)(param_1 + 0x24) = *(int *)(param_1 + 0x24) + -1;
      }
      goto LAB_001f460c;
    }
    iVar4 = FUN_001f69c8(param_1);
    if ((iVar4 == 0xbb) && (iVar4 = FUN_001f69c8(param_1), iVar4 == 0xbf)) goto LAB_001f460c;
    iVar4 = DAT_001f4824 + 0x1f45d2;
    goto LAB_001f46cc;
  }
LAB_001f460c:
  do {
    FUN_001f69c8(param_1);
    iVar4 = *(int *)(param_1 + 0xc);
    if (0x17 < iVar4 - 9U) break;
  } while ((1 << (iVar4 - 9U & 0xff) & 0x800013U) != 0);
  cVar2 = *(char *)(param_1 + 8);
  while ((cVar2 != '\0' && (iVar4 == 0x2f))) {
    iVar4 = FUN_001f69c8(param_1);
    if (iVar4 == 0x2a) {
      while( true ) {
        while (iVar4 = FUN_001f69c8(param_1), iVar4 != 0x2a) {
          if (iVar4 + 1U < 2) {
            iVar4 = DAT_001f4828 + 0x1f46ce;
            goto LAB_001f46cc;
          }
        }
        iVar4 = FUN_001f69c8(param_1);
        if (iVar4 == 0x2f) break;
        iVar4 = *(int *)(param_1 + 0x18);
        *(undefined1 *)(param_1 + 0x10) = 1;
        *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + -1;
        piVar9 = (int *)(param_1 + 0x18);
        if ((iVar4 != 0) ||
           (iVar4 = *(int *)(param_1 + 0x1c), piVar9 = (int *)(param_1 + 0x1c), iVar4 != 0)) {
          *piVar9 = iVar4 + -1;
        }
        if (*(int *)(param_1 + 0xc) != -1) {
          *(int *)(param_1 + 0x24) = *(int *)(param_1 + 0x24) + -1;
        }
      }
    }
    else {
      if (iVar4 != 0x2f) {
        iVar4 = DAT_001f4b54 + 0x1f48d2;
        goto LAB_001f46cc;
      }
      do {
        do {
          iVar4 = FUN_001f69c8(param_1);
        } while (0xe < iVar4 + 1U);
      } while ((0x4803U >> (iVar4 + 1U & 0xff) & 1) == 0);
    }
    do {
      FUN_001f69c8(param_1);
      iVar4 = *(int *)(param_1 + 0xc);
      if (0x17 < iVar4 - 9U) break;
    } while ((1 << (iVar4 - 9U & 0xff) & 0x800013U) != 0);
    cVar2 = *(char *)(param_1 + 8);
  }
  uVar5 = 8;
  switch(iVar4) {
  default:
    goto switchD_001f46ee_caseD_1;
  case 0x22:
    pbVar1 = (byte *)(param_1 + 0x2c);
    if ((*pbVar1 & 1) == 0) {
      uVar3 = 0x22;
      pbVar1[0] = 0;
      pbVar1[1] = 0;
    }
    else {
      **(undefined1 **)(param_1 + 0x34) = 0;
      uVar3 = (undefined1)*(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x30) = 0;
    }
    puVar13 = *(undefined1 **)(param_1 + 0x20);
    if (puVar13 < *(undefined1 **)(param_1 + 0x28)) {
      *puVar13 = uVar3;
      *(undefined1 **)(param_1 + 0x24) = puVar13 + 1;
    }
    else {
      uVar7 = (int)*(undefined1 **)(param_1 + 0x28) - (int)puVar13;
      iVar4 = uVar7 * 2;
      if (uVar7 == 0) {
        iVar4 = 1;
      }
      if (0x3ffffffe < uVar7) {
        iVar4 = 0x7fffffff;
      }
      puVar6 = (undefined1 *)FUN_0007df6a(iVar4);
      *puVar6 = uVar3;
      *(undefined1 **)(param_1 + 0x28) = puVar6 + iVar4;
      *(undefined1 **)(param_1 + 0x20) = puVar6;
      *(undefined1 **)(param_1 + 0x24) = puVar6 + 1;
      if (puVar13 != (undefined1 *)0x0) {
        free(puVar13);
      }
    }
    iVar4 = DAT_001f4b64 + 0x1f4b3c;
LAB_001f4b3a:
    uVar5 = FUN_001f69c8(param_1);
    switch(uVar5) {
    case 0:
      iVar8 = DAT_001f54d8 + 0x1f52ca;
      goto switchD_001f4ffa_caseD_23;
    case 1:
      iVar8 = DAT_001f5428 + 0x1f52d0;
      goto switchD_001f4ffa_caseD_23;
    case 2:
      iVar8 = DAT_001f542c + 0x1f52d6;
      goto switchD_001f4ffa_caseD_23;
    case 3:
      iVar8 = DAT_001f5430 + 0x1f52dc;
      goto switchD_001f4ffa_caseD_23;
    case 4:
      iVar8 = DAT_001f5434 + 0x1f52e2;
      goto switchD_001f4ffa_caseD_23;
    case 5:
      iVar8 = DAT_001f5438 + 0x1f52e8;
      goto switchD_001f4ffa_caseD_23;
    case 6:
      iVar8 = DAT_001f543c + 0x1f52ee;
      goto switchD_001f4ffa_caseD_23;
    case 7:
      iVar8 = (int)&DAT_001f52f4 + DAT_001f5440;
      goto switchD_001f4ffa_caseD_23;
    case 8:
      iVar8 = DAT_001f5444 + 0x1f52fe;
      goto switchD_001f4ffa_caseD_23;
    case 9:
      iVar8 = DAT_001f5448 + 0x1f5304;
      goto switchD_001f4ffa_caseD_23;
    case 10:
      iVar8 = DAT_001f544c + 0x1f530a;
      goto switchD_001f4ffa_caseD_23;
    case 0xb:
      iVar8 = DAT_001f5450 + 0x1f5310;
      goto switchD_001f4ffa_caseD_23;
    case 0xc:
      iVar8 = DAT_001f5454 + 0x1f5316;
      goto switchD_001f4ffa_caseD_23;
    case 0xd:
      iVar8 = DAT_001f5458 + 0x1f531c;
      goto switchD_001f4ffa_caseD_23;
    case 0xe:
      iVar8 = DAT_001f545c + 0x1f5322;
      goto switchD_001f4ffa_caseD_23;
    case 0xf:
      iVar8 = DAT_001f5460 + 0x1f5328;
      goto switchD_001f4ffa_caseD_23;
    case 0x10:
      iVar8 = DAT_001f5464 + 0x1f532e;
      goto switchD_001f4ffa_caseD_23;
    case 0x11:
      iVar8 = DAT_001f5468 + 0x1f5334;
      goto switchD_001f4ffa_caseD_23;
    case 0x12:
      iVar8 = DAT_001f546c + 0x1f533a;
      goto switchD_001f4ffa_caseD_23;
    case 0x13:
      iVar8 = DAT_001f5470 + 0x1f5340;
      goto switchD_001f4ffa_caseD_23;
    case 0x14:
      iVar8 = DAT_001f5474 + 0x1f5346;
      goto switchD_001f4ffa_caseD_23;
    case 0x15:
 
// ... [truncated]

```

