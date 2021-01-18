#! env python3
# adapted from https://qiita.com/amedama/items/698a7c4dbdd34b03b427

import binascii
import dis
import marshal
import sys
import time
import types

INDENT_LEVEL_WIDTH = 4


def get_long(s):
    return s[0] + (s[1] << 8) + (s[2] << 16) + (s[3] << 24)


def show_hex(label, h, indent):
    h = binascii.hexlify(h).decode('ascii')
    if len(h) < 60:
        print('{:s}{:s} {:s}'.format(indent, label, h))
    else:
        print('{:s}{:s}'.format(indent, label))
        for i in range(0, len(h), 60):
            print('{:s}   {:s}'.format(indent, h[i:i + 60]))


def show_code(code, indent=''):
    print('\n{:s}>>> code'.format(indent))

    print('{:s}name {!r:s}'.format(indent, code.co_name))
    print('{:s}argcount {:d}'.format(indent, code.co_argcount))
    print('{:s}varnames {!r:s}'.format(indent, code.co_varnames))
    print('{:s}stacksize {:d}'.format(indent, code.co_stacksize))
    print('{:s}nlocals {:d}'.format(indent, code.co_nlocals))
    print('{:s}names {!r:s}'.format(indent, code.co_names))
    print('{:s}freevars {!r:s}'.format(indent, code.co_freevars))
    print('{:s}cellvars {!r:s}'.format(indent, code.co_cellvars))
    print('{:s}flags {:04x}'.format(indent, code.co_flags))

    #show_hex('code', code.co_code, indent=indent)
    print('{:s}consts'.format(indent))
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            show_code(const, indent + (' ' * INDENT_LEVEL_WIDTH))
        else:
            print('{:s}{!r:s}'.format(indent + (' ' * INDENT_LEVEL_WIDTH), const))

    print('{:s}disassembly {{{{{{'.format(indent))
    dis.disassemble(code)
    print('{:s}}}}}}}'.format(indent))

    #print('{:s}filename {!r:s}'.format(indent, code.co_filename))
    #print('{:s}firstlineno {:d}'.format(indent, code.co_firstlineno))
    #show_hex('lnotab', code.co_lnotab, indent=indent)
    print('{:s}<<< endcode\n'.format(indent))


def show_file(fname: str) -> None:
    with open(fname, 'rb') as f:
        magic_str = f.read(4)
        mtime_str = f.read(4)
        mtime = get_long(mtime_str)
        modtime = time.asctime(time.localtime(mtime))
        print('magic %s' % binascii.hexlify(magic_str))
        print('moddate %s (%s)' % (binascii.hexlify(mtime_str), modtime))
        if sys.version_info < (3, 3):
            print('source_size: (unknown)')
        else:
            source_size = get_long(f.read(4))
            print('source_size: %s' % source_size)

        # one more 4 byte field is here, no idea what it does though so we skip it
        print('unknown field: %s' % f.read(4).hex())

        code = marshal.loads(f.read())
        show_code(code)


if __name__ == '__main__':
    show_file(sys.argv[1])
