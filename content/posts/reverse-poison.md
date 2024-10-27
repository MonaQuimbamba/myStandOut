---
title: "Reverse Eng"
date: 2023-12-15T13:43:53-06:00
draft: false
image: brand_image.jpg
tags: ["x86-64", "ARM"]
series: "Assembly"
---

- Reading time : "8 min"

# The Digital Storm Chronicles

## Episode 1: The Binary Tempest

_A storm rages outside as two security experts face their first challenge_

### Scene 1: The Two Old Cracker Friends

_Thunder crashes outside a dimly lit apartment in C City_

**Monaquimbamba**: "Hey, how are you?"

**Howard**: "Thanks for coming! I'm having trouble with this binary that a winter phenomenon sent to my bitcoin wallet."

```bash
./bitcoinnewallet
arm-binfmt-P: Could not open '/lib/ld-linux.so.3': No such file or directory
```

**Howard**: "Shit, let me check the processor architecture..."

```bash
uname -a
Linux Howard 6.8.0-48-generic #48~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Mon Oct  7 11:24:13 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

**Monaquimbamba**: "Looks like we got a problem. You have an X86 CPU but the binary was changed to ARM architecture. Wait... I remember something about QEMU emulator!"

### Scene 2: The Debug Dance

_Lightning flashes as Monaquimbamba sets up two terminals_

_Terminal 1:_

```bash
gdb-multiarch -q -nx
(gdb) file bitcoinnewallet
Reading symbols from bitcoinnewallet...
(No debugging symbols found in bitcoinnewallet)
(gdb) target remote:8989
Remote debugging using :8989
warning: remote target does not support file transfer, attempting to access files from local filesystem.
warning: Unable to find dynamic linker breakpoint function.
GDB will be unable to debug shared library initializers
and track explicitly loaded dynamic code.
0x3ffdde08 in ?? ()
(gdb) c
Continuing.
[Inferior 1 (process 1) exited with code 05]
```

_Terminal 2:_

```bash
qemu-arm -L /usr/arm-linux-gnueabi/ -g 8989 ./bitcoinnewallet
Please input password
```

### Scene 3: The Ghidra Analysis

_Rain pounds against the windows as they dive into the decompiled code_

```bash

void FUN_00008470(int param_1,int param_2)

{
  size_t sVar1;
  byte *__s;
  int __status;
  int local_14;

  if (param_1 != 2) {
    puts("Please input password");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  __s = *(byte **)(param_2 + 4);
  printf("Checking %s for password...\n",__s);
  sVar1 = strlen((char *)__s);
  if (sVar1 != 6) {
    puts("Loser...");
                    /* WARNING: Subroutine does not return */
    exit(sVar1);
  }
  sVar1 = strlen((char *)__s);
  local_14 = -sVar1 + 6;
  if (*__s != __s[5]) {
    local_14 = -sVar1 + 7;
  }
  if (*__s + 1 != (uint)__s[1]) {
    local_14 = local_14 + 1;
  }
  if (__s[3] + 1 != (uint)*__s) {
    local_14 = local_14 + 1;
  }
  if (__s[2] + 4 != (uint)__s[5]) {
    local_14 = local_14 + 1;
  }
  if (__s[4] + 2 != (uint)__s[2]) {
    local_14 = local_14 + 1;
  }
  __status = local_14 + (__s[3] ^ 0x72) + (uint)__s[6];
  if (__status == 0) {
    puts("Success, you rocks!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Loser...");
                    /* WARNING: Subroutine does not return */
  exit(__status);
}



```

### Scene 4: The C Translation

**Howard**: "Let me clean this up in C programming language..."

```bash

#include <stdio.h>
#include <string.h>




void main(int argc,char **argv){
  size_t len_passwd;
  char *input_passwd;
  int test;
  int local_var;

  if (argc != 2) {
    puts("Please input password");
    /* WARNING: Subroutine does not return */
    exit(1);
  }
  input_passwd = argv[1];
  printf("Checking %s for password...\n",input_passwd);
  len_passwd = strlen((char *)input_passwd);
  if (len_passwd != 6) {
    puts("Loser...");
     /* WARNING: Subroutine does not return */
    exit(len_passwd);
  }


  len_passwd = strlen((char *)input_passwd);
  local_var = -len_passwd + 6;               // local_var =0

  if (*input_passwd != input_passwd[5]) {   // pos[0] != pos[5]
    local_var = -len_passwd + 7;            // local_var =1
  }
  if (*input_passwd + 1 != input_passwd[1]) {  // pos[1] != pos[1] ????
    local_var = local_var + 1;                 // local_var =2
  }
  if (input_passwd[3] + 1 != *input_passwd) {  // pos[4] != pos[0]
    local_var = local_var + 1;                 // local_var =3
  }
  if (input_passwd[2] + 4 != input_passwd[5]) {  // pos[6] != pos[5]
    local_var = local_var + 1;                   // local_var =4
  }
  if (input_passwd[4] + 2 != input_passwd[2]) {  // pos[6] != pos[2]
    local_var = local_var + 1;                   // // local_var =5
  }

  test = local_var + (input_passwd[3] ^ 'r') + input_passwd[6];  // pos[0] != pos[5]

  if (test == 0) {
    puts("Success, you rocks!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Loser...");
                    /* WARNING: Subroutine does not return */
  exit(test);
}
```

**Monaquimbamba**:
"Let me help break down how to exploit this program"

First, let's understand how we can bypass the constraints:

We need a 6-character password that will pass the initial length check
But we also need to access the 7th character (index 6) which is beyond our password length

Let's solve the password constraints we know:

- input_passwd[0] = input_passwd[5] (first and last char must be same)
- input_passwd[0] = input_passwd[3] + 1
- input_passwd[1] = input_passwd[0] + 1
- input_passwd[5] = input_passwd[2] + 4
- input_passwd[2] = input_passwd[4] + 2

The final test equation is:
cCopytest = 5 + (input_passwd[3] ^ 'r') + input_passwd[6] = 0

Exploitation approach:

_We can craft a 6-character password that satisfies the character relationships
Then, by adding a 7th character (which technically shouldn't be allowed), we can control input_passwd[6]
The program will first check length (6 chars) but then still access the 7th byte in memory_

Let's solve this:

- Let's say input_passwd[3] = 'r' so the XOR equals 0
- Then input_passwd[0] = 's' (because [0] = [3] + 1)
- input_passwd[1] = 't' (because [1] = [0] + 1)
- Let's make input_passwd[4] = 'p'
- Then input_passwd[2] = 'r' (because [2] = [4] + 2)
- input_passwd[5] = 'v' (because [5] = [2] + 4)
- Finally input_passwd[6] = -5 (to make final equation = 0)

Therefore, a working exploit would be:

Password: "strprv" (6 characters)
Followed by a byte with value -5 (or 251 in unsigned)

**Howard**: You can try this with something like: **strprv\xFB**

### Scene 5: The Storm's Secret

_Thunder crashes as they attempt their solution_

```bash
qemu-arm -L /usr/arm-linux-gnueabi/ -g 8989 ./exo5 "strprv\xFB"
Checking strprv\xFB for password...
Loser...
```

_Rain intensifies outside, making Monaquimbamba jump_

**Monaquimbamba**: _screaming in fear_ "What is this huge storm?!"

**Howard**: _eyes widening_ "The storm... STORMS! That's it! You're a genius, Monaquimbamba! Let's try that!"

```bash
qemu-arm -L /usr/arm-linux-gnueabi/ -g 8989 ./exo5 "storms"
Checking storms for password...
Success, you rocks!
```
