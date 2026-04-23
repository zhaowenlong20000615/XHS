# libxyass.so — JNI method implementations (decompiled)

## method0 (initializeNative?, 400B) @ `0001f454`

```c

void jni_method0(void)

{
  char in_ZR;
  
  if (in_ZR == '\0') {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}


```

## method1 (INTERCEPT, 2682B) @ `00023e54`

```c

/* WARNING: Restarted to delay deadcode elimination for space: stack */

int * jni_method1(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int *piVar5;
  undefined4 *unaff_r4;
  int *unaff_r8;
  int in_stack_00000004;
  int *in_stack_00000008;
  int iStack0000000c;
  
  iStack0000000c = param_1;
  if (((byte *)unaff_r4[1] != (byte *)*unaff_r4) && (*(byte *)*unaff_r4 - 0x30 < 10)) {
    if (*unaff_r8 == param_1) {
      piVar4 = *(int **)(DAT_00023e08 + 0x23db6);
      iStack0000000c = *piVar4;
      in_stack_00000008 = (int *)FUN_00023f70(unaff_r4);
      if (in_stack_00000008 == (int *)0x0) {
        piVar5 = (int *)0x0;
      }
      else {
        piVar5 = in_stack_00000008;
        if (((char *)unaff_r4[1] != (char *)*unaff_r4) && (*(char *)*unaff_r4 == 'I')) {
          piVar5 = (int *)0x0;
          in_stack_00000004 = FUN_0001ff98(unaff_r4,0);
          if (in_stack_00000004 != 0) {
            piVar5 = (int *)FUN_00020230(unaff_r4,&stack0x00000008,&stack0x00000004);
          }
        }
      }
      iVar3 = *piVar4;
      if (iVar3 == iStack0000000c) {
        return piVar5;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail(iVar3);
    }
    goto LAB_00023f2a;
  }
  iVar3 = FUN_0001e800();
  if (iVar3 == 0) {
    FUN_0001e800();
    in_stack_00000008 = (int *)FUN_00024074();
    if (in_stack_00000008 == (int *)0x0) goto LAB_00023f14;
    piVar4 = in_stack_00000008;
    if (((char *)unaff_r4[1] != (char *)*unaff_r4) && (*(char *)*unaff_r4 == 'I')) {
      piVar4 = (int *)0x0;
      in_stack_00000004 = FUN_0001ff98();
      if (in_stack_00000004 != 0) {
        piVar4 = (int *)FUN_00020230();
      }
    }
  }
  else {
    if (((byte *)unaff_r4[1] == (byte *)*unaff_r4) || (9 < *(byte *)*unaff_r4 - 0x30)) {
      iVar3 = FUN_00023d1c();
    }
    else {
      iVar3 = FUN_00023da4();
    }
    if (iVar3 == 0) {
LAB_00023f14:
      piVar4 = (int *)0x0;
    }
    else {
      piVar4 = (int *)FUN_0001fd44(unaff_r4 + 0x66,0xc);
      iVar2 = DAT_00023f3c;
      iVar1 = DAT_00023f30;
      piVar4[2] = iVar3;
      *piVar4 = iVar2 + 0x23f14;
      piVar4[1] = iVar1;
    }
  }
  if (*unaff_r8 == iStack0000000c) {
    return piVar4;
  }
LAB_00023f2a:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


```

## method2 (initialize, 660B) @ `00025f68`

```c

void jni_method2(undefined4 param_1,int param_2)

{
  int unaff_r5;
  
  FUN_0001fe0e(param_1,param_2 + 0x25f6c,param_2 + 0x25f6d);
                    /* WARNING: Could not recover jumptable at 0x00025f7c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(**(int **)(unaff_r5 + 8) + 0x14))();
  return;
}


```

## method3 (destroy, 202B) @ `000262ec`

```c

/* WARNING: Control flow encountered bad instruction data */

void jni_method3(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

