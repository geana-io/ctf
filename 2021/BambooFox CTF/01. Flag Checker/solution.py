#! env python

target = [
    182, 199, 159, 225, 210, 6, 246, 8, 172, 245, 6, 246, 8, 245, 199, 154,
    225, 245, 182, 245, 165, 225, 245, 7, 237, 246, 7, 43, 246, 8, 248, 215
]

flag = [
    102, 108, 97, 103, 123, 116, 104, 105, 115, 95, 105, 115, 95, 102, 97, 107,
    101, 95, 102, 97, 107, 101, 95, 102, 97, 107, 101, 95, 33, 33, 33, 125
]


def magic(inp, val):
    if val == 0:
        return ((inp >> 3) | (inp << 5)) & 0xff
    elif val == 1:
        return ((inp << 2) | (inp >> 6)) & 0xff
    elif val == 2:
        return (inp + 0b110111) % 0xff
    else:
        return inp ^ 55


def chall(inp):
    val0 = (inp & 0b00000011)
    val1 = (inp & 0b00001100) >> 2
    val2 = (inp & 0b00110000) >> 4
    val3 = (inp & 0b11000000) >> 6

    res0 = magic(inp, val0)
    res1 = magic(res0, val1)
    res2 = magic(res1, val2)
    return magic(res2, val3)


real_flag_candidates = list()
for i in range(32):
    idx_candidates = list()
    for j in range(0xff):
        if chall(j) == target[i]:
            idx_candidates.append(j)
    real_flag_candidates.append(idx_candidates)

real_flag = str()
for i in range(32):
    printable_chars = list(
        filter(lambda c: 0x21 <= c and c <= 0x7e, real_flag_candidates[i]))
    if len(printable_chars) == 1:
        real_flag += chr(printable_chars[0])
    else:
        real_flag += "["
        for c in printable_chars:
            real_flag += chr(c)
        real_flag += "]"
print(real_flag)

# real flag
# flag{v3r[]_v3r1log_f14g_ch3ck3r!}
# missing character is 'y', meaning the value 172 in target should be 168
