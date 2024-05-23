#!/usr/bin/python3
import sys, struct

PAGE_SIZE = 0x1000
OFFSET_LC_COUNT = 0x10

HLT_KERNEL_BOOTSTRAP_AFTER_PRINT = True

# msr daifset, #0xf
NO_INTER = b"\xdf\x4f\x03\xd5"
LOOP = bytes.fromhex('0000 0014')

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

def size_page_high(n):
    return (n-1) // PAGE_SIZE * PAGE_SIZE + PAGE_SIZE

def page_low(n):
    return (n) // PAGE_SIZE * PAGE_SIZE

def n_unpack(i, n):
    if i >= (1 << (n-1)):
        return -(1 << n) + i
    return i

#ive made bad decisions
def get_insn(offset):
    return struct.unpack("<I", ink[offset:offset+4])[0]

def is_retab(insn):
    return insn == 0xd65f0fff

def is_bl(insn):
    return insn & 0xfc000000 == 0x94000000

def is_adrp(insn):
    return insn & 0x9f000000 == 0x90000000

def get_imm_b_offset(insn):
    return n_unpack(insn & 0x03ffffff, 26) << 2

def get_cstring(offset):
    return ink[offset: ink.index(b'\0', offset)].decode(errors="ignore")

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
HOOK_VM_BASE = size_page_high(max_seg[0] + max_seg[1])

print(f"[*] Base of hook {HOOK_VM_BASE:x}")

# find segment with addr
def get_vma_seg(addr):
    return next(filter(lambda s: s[0] + s[1] > addr >= s[0], segs))


def get_file_seg(addr):
    return next(filter(lambda s: s[2] + s[3] > addr >= s[2], segs))

entry_seg = get_vma_seg(INIT_PC)

def vma_to_file(n):
    s = get_vma_seg(n)
    return n - s[0] + s[2]


def file_to_vma(n):
    s = get_file_seg(n)
    return n - s[2] + s[0]


# assembles an adrp_insn, takes own vma and target vma
def adrp_pack(target, vma_location, rd):
    offset = (target - page_low(vma_location)) >> 12
    offset &= 0x1fffff

    #const
    insn = 0x90000000
    
    #immlo
    insn |= (offset << 29) & 0x60000000
    insn |= (offset << 3) & 0x00ffffe0
    insn |= rd & 0x1f

    return insn

# takes insn and location of insn in file and spits out vma of target page
def adrp_unpack(n, file_location):
    imm = (n & 0x60000000) >> 29
    imm += (n & 0x00ffffe0) >> 3
    imm = n_unpack(imm, 21) << 12
    return page_low(file_to_vma(file_location)) + imm

def add_imm_unpack(n):
    return (n & 0x003ffc00) >> 10

def inc_imm_pack(r, imm):
    insn = 0x91000000
    insn |= (imm & 0xfff) << 10
    insn |= (r & 0x1f) << 5
    insn |= r & 0x1f
    return insn

def get_first_insn_from(n, f, reverse=False):
    insn = get_insn(n)
    while not f(insn):
        n += 4 if not reverse else -4
        insn = get_insn(n)
    return n


# this could change between builds maybe? but doubt it
assert entry_seg[4] == "__TEXT_EXEC\0\0\0\0\0"

entry_file_off = vma_to_file(INIT_PC)

OFFSET_INJECT = entry_file_off

# there is a b (roughly) #0x3000 here which goes to start_first_cpu
# we'll patch this with our own insn, disable IRQs and put the original one with the offset decremented
# if this changes we have to do a different injection which is annoying
tramp_insn = get_insn(entry_file_off)

r_start_first_cpu = get_imm_b_offset(tramp_insn)

print(f"[*] start_first_cpu trampoline: b #0x{r_start_first_cpu*4:x} ({tramp_insn:08x})")

# 4 insns
r_start_first_cpu_new = r_start_first_cpu - 16

tramp_insn = (5 << 26) + ((r_start_first_cpu_new) >> 2 & 0x03ffffff)


print(f"[*] patched start_first_cpu trampoline: b #0x{r_start_first_cpu*4:x} ({tramp_insn:08x})")

# bl hook
hook_tramp_insn = (37<<26) + (((HOOK_VM_BASE - INIT_PC - 12) >> 2) & 0x03ffffff)


hook = b''

with open(sys.argv[2], 'rb') as f:
    hook = f.read()

#page align hook (probably not required)
hook += b'\0' * (size_page_high(len(hook)) - len(hook))

string_vma = HOOK_VM_BASE + len(hook)

print(f"  output buffer@ {string_vma:x}")

# msr daifset, #0xf
# adrp x1, page: <string>
# add x1, <string>@page
# bl hook
# b start_first_cpu
inject = NO_INTER

inject += struct.pack('<I', adrp_pack(string_vma, INIT_PC, 1))
inject += struct.pack('<I', inc_imm_pack(1, string_vma & 0xfff))

inject += struct.pack('<I', hook_tramp_insn)
inject += struct.pack('<I', tramp_insn)

# sanity:
# test_insn = struct.unpack('<I', inject[4:8])[0]
# print(test_insn)
# vma = adrp_unpack(test_insn, OFFSET_INJECT+4)
# vma += add_imm_unpack(struct.unpack('<I', inject[8:12])[0])
# print(hex(vma))
# print(hex(string_vma))
# print(get_cstring(vma_to_file(vma)))

# output buffer
output_buffer = b'Hello world!'.ljust(PAGE_SIZE, b'\0')
hook += output_buffer

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

def patch(k, b, o):
    return k[:o] + b + k[o+len(b):]

outk = ink[:OFFSET_LC_COUNT]
outk += struct.pack('<I', NUM_LOAD)
outk += ink[OFFSET_LC_COUNT + 4:OFFSET_LC]
outk += lc
outk += ink[OFFSET_LC + len(lc):]
outk += hook


print(f"[*] Hooking entry@ {OFFSET_INJECT}")
outk = patch(outk, inject, OFFSET_INJECT)

if HLT_KERNEL_BOOTSTRAP_AFTER_PRINT:
    print("[*] Patching kernel_bootstrap")
    
    '''
    void
    kernel_bootstrap(void)
    {
        kern_return_t   result;
        thread_t        thread;
        char            namep[16];

        printf("%s\n", version); /* log kernel version */

        scale_setup(); <----- OFFSET OF THIS

        kernel_bootstrap_log("vm_mem_bootstrap");
        vm_mem_bootstrap();

    '''
    OFFSET_KERNEL_BOOTSTRAP_AFTER_PRINT = None
    
    vma_start_first_cpu = INIT_PC + r_start_first_cpu
    file_start_first_cpu = vma_to_file(vma_start_first_cpu)
    
    print(f"  start_first_cpu at {file_start_first_cpu}")

    insn = get_insn(file_start_first_cpu)

    while insn & 0x9f00001f != 0x9000001e:
        file_start_first_cpu += 4
        insn = get_insn(file_start_first_cpu)

    next_page = vma_to_file(adrp_unpack(insn, file_start_first_cpu))

    file_start_first_cpu += 4
    insn = get_insn(file_start_first_cpu)

    arm_init = next_page + add_imm_unpack(insn)

    print(f"  arm_init at {arm_init}")

    known_syms = {
        0x1699d2c: "kernel_debug_string_early",
        0x1d43fb0: "PE_parse_boot_argn",
        0x1d44724: "PE_get_default",
        0x15a851c: "printf",
        0x15c30e0: "kernel_bootstrap"
    }

    def get_close_string_param(addr, target):
        #address of adrp before call
        # adrp = get_first_insn_from(addr, lambda i: i & 0x9f00001f == 0x90000001, reverse=True)
        adrp = get_first_insn_from(addr, lambda i: i & 0x9f000000 == 0x90000000, reverse=True)

        #page addr
        a = adrp_unpack(get_insn(adrp), adrp)

        #page offset
        a += add_imm_unpack(get_insn(adrp + 4))

        string = get_cstring(vma_to_file(a))
        print(f"{a:x}: {string}",)


    def fn_call_dumps(start, end):
        # string dumps
        for addr in range(start, end, 4):
            insn = get_insn(addr)
            if not is_bl(insn):
                continue
            
            offset = get_imm_b_offset(insn)
            target = addr + offset

            # these offsets are gonna break for a different kc, you'll have to find them again
            # print(f"Function call: {target}, offset from function: {hex((offset + (addr - start)) % (1<<64))}")
            if target == 30685616 or target == 30897652:
                get_close_string_param(addr, target)

    # fn_call_dumps(arm_init, arm_init_ret)

    def fn_string_dumps(start):
        end = get_first_insn_from(start, is_retab)

        strings = []

        i = start - 4
        while (i := i + 4 ) < end:

            insn = get_insn(i)

            if is_adrp(insn):
                vma  = adrp_unpack(insn, i)
                i += 4
                insn = get_insn(i)
                vma += add_imm_unpack(insn)
                strings.append((get_cstring(vma_to_file(vma)), (i-start) // 4))
            
            elif is_bl(insn):
                offset = get_imm_b_offset(insn)
                target = i + offset

                print(f"({(i - start) // 4}) Calling function: {target:x}, ({known_syms.get(target)}), collected strings: {strings}")
                strings = []

    #and x8, x0, #0xffffffffffff00ff
    stack_canary_and = get_first_insn_from(arm_init, lambda i: i & 0xfffffc00 == 0x9270dc00)

    machine_startup_call = get_first_insn_from(stack_canary_and, is_bl)

    # print(f"Patching machine_startup call@ {machine_startup_call}")
    # outk = patch(outk, LOOP, machine_startup_call)

    machine_startup = get_imm_b_offset(get_insn(machine_startup_call)) + machine_startup_call

    print(f"  machine_startup at {machine_startup}")

    machine_conf_call = get_first_insn_from(machine_startup, is_bl)
    kernel_bootstrap_call = get_first_insn_from(machine_conf_call + 4, is_bl)

    kernel_bootstrap = get_imm_b_offset(get_insn(kernel_bootstrap_call)) + kernel_bootstrap_call

    print(f"  kernel_bootstrap at {kernel_bootstrap}")

    subs_adrp = get_first_insn_from(kernel_bootstrap, is_adrp)
    format_string_adrp = get_first_insn_from(subs_adrp + 4, is_adrp)

    
    inject = struct.pack('<I', adrp_pack(string_vma, file_to_vma(format_string_adrp), 0))
    inject += struct.pack('<I', inc_imm_pack(0, string_vma & 0xfff))

    outk = patch(outk, inject, format_string_adrp)

    # loop before machine_lockdown
    # this probably just needs to happen anywhere after initialize_screen()
    # use source plus fn_string_dumps to figure out this offset

    outk = patch(outk, NO_INTER + LOOP, kernel_bootstrap + (1500 * 4))

open(sys.argv[1]+".patched", 'wb').write(outk)
