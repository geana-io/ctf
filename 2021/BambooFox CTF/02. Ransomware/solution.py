#! env python3

import requests
from Cryptodome.Cipher import AES

material = requests.get('https://ctf.bamboofox.tw/rules').text.encode()
with open('flag.enc', 'rb') as f:
    data = f.read()

cipher = AES.new(material[99:99 + 16], AES.MODE_CBC, material[153:153 + 16])

with open('flag.png', 'wb') as f:
    f.write(cipher.decrypt(data))

# running binwalk on the resulting file clearly shows that there is a second png
# image at offset 0xC5672
#
# DECIMAL       HEXADECIMAL     DESCRIPTION
# --------------------------------------------------------------------------------
# 0             0x0             PNG image, 980 x 746, 8-bit/color RGBA, non-interlaced
# 41            0x29            Zlib compressed data, default compression
# 808562        0xC5672         PNG image, 980 x 492, 8-bit/color RGBA, non-interlaced
# 808603        0xC569B         Zlib compressed data, default compression
