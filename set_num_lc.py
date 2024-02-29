#!/usr/bin/python3
import sys, struct

#OFFSET = 22266080
OFFSET = 0x10

ink = open(sys.argv[1], 'rb').read()
p = struct.pack("<I", int(sys.argv[2]))
outk = ink[:OFFSET]
outk += p
outk += ink[OFFSET + len(p):]
open(sys.argv[1]+".patched", 'wb').write(outk)
