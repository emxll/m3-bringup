#!/usr/bin/python3
import struct, sys


off = 0

b = None

extract = 0
extend_data = 1

PLATFORM_TYPES = {
    0x1: "MacOS",
    0x2: "iPhone IOS",
    0x3: "Apple TV Box",
    0x4: "Apple Watch",
    0x5: "Bridge OS",
    0x6: "Mac Catalyst",
    0x7: "iPhone IOS simulator",
    0x8: "Apple TV simulator",
    0x9: "Apple watch simulator",
    0xA: "Driver KIT",
    0xB: "Apple Vision Pro",
    0xC: "Apple Vision Pro simulator"
}

TOOL_TYPES = {
    0x1: "CLANG",
    0x2: "SWIFT",
    0x3: "LD"
}

with open(sys.argv[1], "rb") as f:
    b = f.read()

print()

off += 0x10

def int_1():
    global off

    off += 1
    return struct.unpack("<B", b[off-1:off])[0]

def int_2():
    global off

    off += 2
    return struct.unpack("<H", b[off-2:off])[0]

def int_4():
    global off

    off += 4
    return struct.unpack("<I", b[off-4:off])[0]

def int_8():
    global off

    off += 8
    return struct.unpack("<Q", b[off-8:off])[0]

NUM_LOAD = int_4()


print("[*]  Mach-O Header:")
print(f"Number of load commands: {NUM_LOAD}")


off += 0xc

print()

def read_version():
    parts = (int_1(), int_1(), int_2())
    print(f"version: {parts[2]}.{parts[1]}.{parts[0]}")

def read_tool():
    print(f"Tool Type: {TOOL_TYPES.get(int_4(), 'Not specified')}")
    print("Tool ", end="")
    read_version()

def read_load_command():
    global off

    global VMADDR_TOP
    global VMADDR_BASE
    global output

    CMD_LOAD = int_4()
    CMD_SIZE = int_4()

    pre = None

    if CMD_LOAD & 0x80000000:
        CMD_LOAD &= 0x7fffffff
        pre = "[*]  Load command (required): "
    else:
        pre = "[*]  Load command: "


    if CMD_LOAD == 0x05:
        print(pre, end="")
        print("Register state (0x5)")
        flavor = int_4()
        assert flavor == 6, "Unknown thread state information command"

        #32 regs + fields
        off += 32*8 + 4
        pc = int_8()
        print(f"Entrypoint: 0x{pc:x}")

        print()

        #cpsr
        off += 8

    elif CMD_LOAD == 0x1b:
        print(pre, end="")
        print("Application UUID number (0x1b)")
        uuid = b[off:off+16].hex()
        off += 16
        print(f"UUID {uuid}")
        print()

    elif CMD_LOAD == 0x32:
        print(pre, end="")
        print("Minimum OS version (0x32)")
        print(f"Platform Type: {PLATFORM_TYPES.get(int_4(), 'Not specified')}")
        print("Minimum OS ", end="")
        read_version()
        print("SDK ", end="")
        read_version()

        num_tools = int_4()
        for i in range(num_tools):
            read_tool()
        print()

    elif CMD_LOAD == 0x19:
        print(pre, end="")
        print("64-bit segment load (0x19)")

        off += 16

        vm_base = int_8()
        vm_size = int_8()
        file_base = int_8()
        file_size = int_8()

        print(f"Segment name {b[off-48:off-32].decode('latin-1', errors='ignore')}, vm: {vm_base:x}-{vm_base + vm_size:x}, file: {file_base}-{file_base+file_size}")

        if not extract:
            off += -32 -16 -8 + CMD_SIZE
            print()
            return

        if file_base == 0 or 0:
            off += -32 -16 -8 + CMD_SIZE
            print("Passing")
            print()
            return


        if VMADDR_BASE is None:
            VMADDR_BASE = vm_base
            VMADDR_TOP = vm_base

        zeroes = vm_base - VMADDR_TOP

        assert zeroes < 0x1000, f"Max. hole size is 1 page, bytes: {zeroes}"

        output += b'\0' * zeroes

        VMADDR_TOP += zeroes

        output += b[file_base:file_base+file_size]

        VMADDR_TOP += file_size

        off += -32 -16 -8 + CMD_SIZE

        print()
    elif CMD_LOAD == 0x35:
        # there is another load command, 0x35, which is kc specific i think
        # format:
        # 0x80000035 (type)
        # 0x38, 0x40, 0x48 (usually, but varies. Always 8 byte aligned)
        # vmaddr 8bytes
        # file offset
        # long long 0x20 (???)
        # name in ascii (e.g. com.appe.driver.AplleConvergedIPCOLYBTControl)
        print(pre, end="")
        print("KernelCache Ext descriptor (0x35)")

        vm_base = int_8()
        file_base = int_8()

        off += 8

        print(f"Ext name {b[off:off+CMD_SIZE-0x20].decode('latin-1', errors='ignore')}, vm: {vm_base:x}, file: {file_base}")

        off += CMD_SIZE - 0x20

        print()

    else:
        # print(pre, end="")
        # print(f"Unknown Load command 0x{CMD_LOAD:x}")
        # exit()
        off += CMD_SIZE - 8

VMADDR_BASE = None
VMADDR_TOP = None

output = b''

for i in range(NUM_LOAD):
    read_load_command()

with open(sys.argv[2], "wb") as f:
    f.write(output)
    if extend_data:
        f.write(b'\0' * 0x2000)
