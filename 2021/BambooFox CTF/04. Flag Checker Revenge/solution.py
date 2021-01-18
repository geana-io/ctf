#! env python3

flag = [0] * 0x2b

flag[5   ] = 52
flag[1   ] = 108
flag[0x17] = 95
flag[2   ] = 97
flag[0xf ] = 121
flag[0x1c] = 51
flag[0x12] = 48
flag[0x26] = 55
flag[0x19] = 51
flag[0x10] = 95
flag[0x27] = 49
flag[0x15] = 104
flag[7   ] = 108
flag[6   ] = 108
flag[0x1b] = 112
flag[0x13] = 95
flag[0xc ] = 95
flag[0x14] = 55
flag[0x28] = 48
flag[3   ] = 103
flag[0x1d] = 53
flag[0   ] = 102
flag[0x1a] = 51
flag[0x25] = 52
flag[0x1f] = 95
flag[0x18] = 100
flag[0x21] = 52
flag[0x20] = 118
flag[0x22] = 108
flag[4   ] = 123
flag[0x24] = 100
flag[0x16] = 51
flag[0xb ] = 51
flag[0xd ] = 119
flag[0x11] = 55
flag[9   ] = 55
flag[0x1e] = 55
flag[0x23] = 49
flag[0x2a] = 125
flag[0x29] = 110
flag[0xe ] = 52
flag[0xa ] = 104
flag[8   ] = 95

s = str()
for c in flag:
    s += chr(c)
print(s)
