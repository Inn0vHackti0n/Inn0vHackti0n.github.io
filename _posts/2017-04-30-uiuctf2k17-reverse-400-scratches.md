---
layout: post
title: "[UIUCTF2k17] Reverse 400 - Scratches"
categories: writeup
---
States:
```
nc challenge.uiuc.tf 11347

every day I do
100 push ups
100 sit ups
100 squats
100 crackmes

ALL YOUR SOLUTIONS SHOULD BE ASCII

https://www.youtube.com/watch?v=ElGLWB5ffGk
```

Hello everyone !

This one was a bit tricky, since the gloal was to break 100 crackmes.

At connection, the TCP service send you a huge `base64` string, which is an ELF encoded binary then asking you for a flag .. Like this:

```
[BASE64]
What is the flag ?
<< flag
>> [Good Boy|Bad Boy]
[BASE64]
What is the flag ?
[ETC ETC ]
```

First analyse the binary ..
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@3
  __int64 v4; // rcx@7
  int i; // [sp+28h] [bp-58h]@1
  char buf[32]; // [sp+30h] [bp-50h]@1
  char s[8]; // [sp+50h] [bp-30h]@1
  __int64 v8; // [sp+68h] [bp-18h]@1

  v8 = *MK_FP(__FS__, 40LL);
  read(0, buf, 0x11uLL);
  strcpy(s, "vkakmltocmkwwrvzd");
  for ( i = 0; i < strlen(s); ++i )
  {
    if ( s[i] != buf[i] )
    {
      puts("sounds fake but ok");
      result = 1;
      goto LABEL_7;
    }
  }
  puts("you got it!");
  result = 0;
LABEL_7:
  v4 = *MK_FP(__FS__, 40LL) ^ v8;
  return result;
}
```

Here is the Pseudo code, pretty easy, but the flag is a random generated string, which is in the .text section :

```shell
/ (fcn) main 228
|   main ();
|           ; var int local_78h @ rbp-0x78
|           ; var int local_70h @ rbp-0x70
|           ; var int local_64h @ rbp-0x64
|           ; var int local_59h @ rbp-0x59
|           ; var int local_58h @ rbp-0x58
|           ; var int local_54h @ rbp-0x54
|           ; var int local_50h @ rbp-0x50
|           ; var int local_30h @ rbp-0x30
|           ; var int local_28h @ rbp-0x28
|           ; var int local_20h @ rbp-0x20
|           ; var int local_18h @ rbp-0x18
|              ; DATA XREF from 0x0040054d (entry0)
|           0x00400626      55             push rbp
|           0x00400627      4889e5         mov rbp, rsp
|           0x0040062a      53             push rbx
|           0x0040062b      4883ec78       sub rsp, 0x78               ; 'x'
|           0x0040062f      897d9c         mov dword [rbp - local_64h], edi
|           0x00400632      48897590       mov qword [rbp - local_70h], rsi
|           0x00400636      48895588       mov qword [rbp - local_78h], rdx
|           0x0040063a      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=0x1a88 ; '('
|           0x00400643      488945e8       mov qword [rbp - local_18h], rax
|           0x00400647      31c0           xor eax, eax
|           0x00400649      488d45b0       lea rax, qword [rbp - local_50h]
|           0x0040064d      ba11000000     mov edx, 0x11               ; rdx ; size_t nbyte
|           0x00400652      4889c6         mov rsi, rax                ; void *buf
|           0x00400655      bf00000000     mov edi, 0                  ; int fildes
|           0x0040065a      b800000000     mov eax, 0
|           0x0040065f      e89cfeffff     call sym.imp.read          ; ssize_t read(int fildes, void *buf, size_t nbyte)
|           0x00400664      48b8766b616b.  movabs rax, 0x6f746c6d6b616b76 ; Flag 1 0x6f746c6d6b616b76·at adress 0x400666
|           0x0040066e      488945d0       mov qword [rbp - local_30h], rax
|           0x00400672      48b8636d6b77.  movabs rax, 0x7a767277776b6d63 ; Flag 2  0x7a767277776b6d63 at adress 0x400674
|           0x0040067c      488945d8       mov qword [rbp - local_28h], rax
|           0x00400680      66c745e06400   mov word [rbp - local_20h], 0x64 ; 'd' Flag 3 0x64 at adress 0x00400680
|           0x00400686      c745a8000000.  mov dword [rbp - local_58h], 0
|       ,=< 0x0040068d      eb3a           jmp 0x4006c9
```

Btw, I inserted asm comment for you to see the flag fragments.
Now We should we have to write an automated script, that will do some I/O stuff and ELF Reading (Python pwntools is doing everything for us)
Here is the script :

```python
#!/usr/bin/env python2

from pwn import *
from time import sleep
from sys import exit

s = remote('challenge.uiuc.tf', 11347)
for i in range(100):
    content = s.recvuntil("What's the flag?")
    content = content.split('What')[0].replace('\n', '').decode('base64')
    f = open('/tmp/%d' % (i), 'w+')
    f.write(content)
    f.close()
    context.log_level = 'error'
    elf = ELF('/tmp/%d' % (i))
    context.log_level = 'info'
    flag = elf.read(0x400666, 8)
    flag += elf.read(0x400674, 8)
    flag += elf.read(0x400684, 1)
    s.sendline(flag)
    data = s.recvline()
    data += s.recvline()
    log.success(data.strip() + " FOR BINARY %d flag %s" % (i, flag))
    if "wrong" in data:
        print content
        exit(0)
log.success(s.recvall())
s.close()
```

Fun challenge !

SakiiR'
