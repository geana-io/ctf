#! env python3

what = [
    0x17, 0x2F, 0x27, 0x17, 0x1D, 0x4A, 0x79, 0x03, 0x2C, 0x11, 0x1E, 0x26,
    0x0A, 0x65, 0x78, 0x6A, 0x4F, 0x4E, 0x61, 0x63, 0x41, 0x2D, 0x26, 0x01,
    0x4C, 0x41, 0x4E, 0x48, 0x27, 0x2E, 0x26, 0x12, 0x3E, 0x23, 0x27, 0x5A,
    0x0F, 0x4F, 0x0B, 0x25, 0x3A, 0x28, 0x26, 0x48, 0x49, 0x0C, 0x4A, 0x79,
    0x6C, 0x4C, 0x27, 0x1E, 0x6D, 0x74, 0x64, 0x43
]

secret = [
    0x42, 0x0A, 0x7C, 0x5F, 0x22, 0x06, 0x1B, 0x67, 0x37, 0x23, 0x5C, 0x46,
    0x0A, 0x29, 0x09, 0x30, 0x51, 0x38, 0x5F, 0x7B, 0x59, 0x13, 0x18, 0x0D,
    0x50
]

# i do not know the first character of the input
# so i try any value
for c in range(0xff):
    candidate = [c]
    abort = False

    # i try to see if i can recover a string with printable ascii characters
    # and without space, that would pass the check function
    for i in range(1, len(what)):
        nc = candidate[i - 1] ^ what[i - 1]
        if 0x21 <= nc and nc <= 0x7e:
            candidate.append(nc)
        else:
            abort = True
            break

    # potential candidate what passes the check function
    # let's try to decrypt and see what we get
    if not abort:
        flag = str()
        for i in range(len(candidate)):
            flag += chr(secret[i % len(secret)] ^ candidate[i])
        print(flag)
        # one of the printed strings is 7h15_f14g_15_v3ry_v3ry_l0ng_4nd_1_h0p3_th3r3_4r3_n0_7yp0