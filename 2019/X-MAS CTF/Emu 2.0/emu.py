#! env python3

import sys

debug = False
def log(message):
    if debug:
        print(message)
        sys.stdout.flush()

class Emulator:

    def __init__(self, rom_file):
        self.a = 0
        self.pc = 0x100
        with open(rom_file, 'rb') as f:
            rom = f.read()

        self.memory = dict()
        for i in range(len(rom)):
            self.memory[0x100 + i] = rom[i]

        self.blocked_addresses = list()

    def _read(self, address):
        return self.memory.get(address, 0)

    def _write(self, address, value):
        if address not in self.blocked_addresses:
            if value == 0:
                del self.memory[address]
            else:
                self.memory[address] = value

    def _extract_address(self, opcode):
        return ((opcode[0] & 0x0f) << 8) + opcode[1]

    def _compare_a(self, val):
        if self.a == val:
            self.a = 0
        elif self.a < val:
            self.a = 1
        else:
            self.a = 0xff

    def _fetch(self):
        opcode = list()
        opcode.append( self._read(self.pc) )
        opcode.append( self._read(self.pc + 1) )
        self.pc += 2
        return opcode

    def _decode(self, opcode):
        if opcode[0] == 0x24 and opcode[1] == 0x08:
            exit(0)

        log('{:02x}{:02x}'.format(opcode[0], opcode[1]))

        # Arithmetic
        if opcode[0] == 0x00:
            original_a = self.a
            self.a += opcode[1]
            if self.a >= 256:
                self.a = self.a % 256
            log("A ({:02x}) += {:02x} = {:02x}".format(original_a, opcode[1], self.a))

        elif opcode[0] == 0x01:
            self.a = opcode[1]

        elif opcode[0] == 0x02:
            self.a = self.a ^ opcode[1]

        elif opcode[0] == 0x03:
            self.a = self.a | opcode[1]

        elif opcode[0] == 0x04:
            self.a = self.a & opcode[1]

        elif (opcode[0] >> 4) == 0x8:
            address = self._extract_address(opcode)
            self.a = self._read(address)
            log("A = ptr[{:03x}] = {:02x}".format(address, self.a))

        elif (opcode[0] >> 4) == 0xd:
            address = self._extract_address(opcode)
            aux = self._read(address)
            self._write(address, self.a ^ aux)

        elif (opcode[0] >> 4) == 0xf:
            address = self._extract_address(opcode)
            self._write(address, self.a)
            log("[{:03x}] = A".format(address))

        # I/O
        elif opcode[0] == 0x13 and opcode[1] == 0x37:
            if debug == True:
                print(chr(self.a), " {:02x}".format(self.a))
            else:
                print(chr(self.a), end="")
            sys.stdout.flush()

        # Control Flow
        elif (opcode[0] >> 4) == 0x2:
            self.pc = self._extract_address(opcode)

        elif (opcode[0] >> 4) == 0x3:
            if self.a == 0:
                self.pc = self._extract_address(opcode)

        elif (opcode[0] >> 4) == 0x4:
            if self.a == 1:
                self.pc = self._extract_address(opcode)

        elif (opcode[0] >> 4) == 0x5:
            if self.a == 0xff:
                self.pc = self._extract_address(opcode)

        elif opcode[0] == 0x60:
            original_a = self.a
            self._compare_a(opcode[1])
            log("compare A ({:02x}) with {:02x}".format(original_a, opcode[1]))

        elif (opcode[0] >> 4) == 0x7:
            original_a = self.a
            address = self._extract_address(opcode)
            val = self._read(address)
            self._compare_a(val)
            log("compare A ({:02x}) with [{:03x}] ({:02x})".format(original_a, address, val))

        elif opcode[0] == 0xbe and opcode[1] == 0xef:
            self.a = 0x42
            self.pc = 0x100

        # Security
        elif (opcode[0] >> 4) == 0x9:
            address = self._extract_address(opcode)
            self.blocked_addresses.append(address)

        elif (opcode[0] >> 4) == 0xa:
            address = self._extract_address(opcode)
            self.blocked_addresses.remove(address)

        elif (opcode[0] >> 4) == 0xc:
            address = self._extract_address(opcode)
            val = self._read(address)
            self._write(address, val ^ 0x42)

        # Misc
        elif opcode[0] == 0xee and opcode[1] == 0xee:
            pass

        # Unknown
        else:
            self.a -= 1

    def run(self):
        while True:
            opcode = self._fetch()
            self._decode(opcode)

emu = Emulator('rom')
emu.run()
