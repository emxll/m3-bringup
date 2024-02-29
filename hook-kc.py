#!/usr/bin/python3
import sys, struct

PAGE_SIZE = 0x4000
OFFSET_LC_COUNT = 0x10

ink = open(sys.argv[1], 'rb').read()

off = 0

off += 0x10

def int_1():
    global off

    off += 1
    return struct.unpack("<B", ink[off-1:off])[0]

def int_2():
    global off

    off += 2
    return struct.unpack("<H", ink[off-2:off])[0]

def int_4():
    global off

    off += 4
    return struct.unpack("<I", ink[off-4:off])[0]

def int_8():
    global off

    off += 8
    return struct.unpack("<Q", ink[off-8:off])[0]

def page_high(n):
    return (n-1) // PAGE_SIZE * PAGE_SIZE + PAGE_SIZE

NUM_LOAD = int_4()

print(f"[*] Number of load commands: {NUM_LOAD}")

off += 0xc

INIT_PC = None

#haha
segs = []

for i in range(NUM_LOAD):
    CMD_LOAD = int_4()
    CMD_SIZE = int_4()

    if CMD_LOAD & 0x80000000:
        CMD_LOAD &= 0x7fffffff


    if CMD_LOAD == 0x05:
        flavor = int_4()

        #this might be dumb, try removing this
        assert flavor == 6, "Unknown thread state information command"

        #32 regs + fields
        off += 32*8 + 4
        pc = int_8()
        INIT_PC = pc

        #cpsr
        off += 8

    #LC_SEGMENT_64
    elif CMD_LOAD == 0x19:
        name = ink[off:off+16].decode('latin-1', errors='ignore')

        off += 16

        vm_base = int_8()
        vm_size = int_8()
        file_base = int_8()
        file_size = int_8()

        segs.append((vm_base, vm_size, file_base, file_size, name, off-56, CMD_SIZE))

        off += CMD_SIZE - 56

    else:
        off += CMD_SIZE - 8

assert INIT_PC is not None

print(f"[*] Entry point {INIT_PC:x}")

#hook location, behind kernel
max_seg = max(segs, key=lambda s: s[0]+s[1])
HOOK_VM_BASE = page_high(max_seg[0] + max_seg[1])

print(f"[*] Base of hook {HOOK_VM_BASE:x}")

# find segment with entry point
entry_seg = next(filter(lambda s: s[0] + s[1] > INIT_PC >= s[0], segs))

# this could change between builds maybe? but doubt it
assert entry_seg[4] == "__TEXT_EXEC\0\0\0\0\0"

entry_file_off = INIT_PC - entry_seg[0] + entry_seg[2]

OFFSET_INJECT = entry_file_off

# there is a b (roughly) #0x3000 here which goes to start_first_cpu
# we'll patch this with our own insn, disable IRQs and put the original one with the offset decremented
# if this changes we have to do a different injection which is annoying
tramp_insn = struct.unpack('<I', ink[entry_file_off:entry_file_off+4])[0]

r_start_first_cpu = tramp_insn & 0x03ffffff

print(f"[*] start_first_cpu trampoline: b #0x{r_start_first_cpu*4:x} ({tramp_insn:08x})")

# two insns
r_start_first_cpu -= 2
tramp_insn = (5 << 26) + (r_start_first_cpu & 0x03ffffff)


print(f"[*] patched start_first_cpu trampoline: b #0x{r_start_first_cpu*4:x} ({tramp_insn:08x})")

# bl hook
hook_tramp_insn = (37<<26) + (((HOOK_VM_BASE - INIT_PC - 4) >> 2) & 0x03ffffff)

# msr daifset, #0xf
# bl hook
# b start_first_cpu
inject = b"\xdf\x4f\x03\xd5"
inject += struct.pack('<I', hook_tramp_insn)
inject += struct.pack('<I', tramp_insn)

hook = b''

with open(sys.argv[2], 'rb') as f:
    hook = f.read()

#page align hook (probably not required)
hook += b'\0' * (page_high(len(hook)) - len(hook))

# Increase segment size

#file size = vm size (doesn't have to be true but cba)
assert max_seg[1] == max_seg[3]

print(f"[*] Patching {max_seg[4]} size {max_seg[1]} new size {max_seg[1] + len(hook)}")

OFFSET_LC = max_seg[5] + 32


lc = struct.pack('<Q', max_seg[1] + len(hook))
lc += struct.pack('<Q', max_seg[2])
lc += struct.pack('<Q', max_seg[1] + len(hook))

#perms
lc += struct.pack('<I', 5)
lc += struct.pack('<I', 5)

print("[*] Patching kc")

outk = ink[:OFFSET_LC_COUNT]
outk += struct.pack('<I', NUM_LOAD)
outk += ink[OFFSET_LC_COUNT + 4:OFFSET_LC]
outk += lc
outk += ink[OFFSET_LC + len(lc):OFFSET_INJECT]
outk += inject
outk += ink[OFFSET_INJECT + len(inject):]
outk += hook
open(sys.argv[1]+".patched", 'wb').write(outk)
