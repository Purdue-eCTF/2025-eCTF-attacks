#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf

context.arch = 'thumb'

def conn():
    r = DecoderIntf('/dev/ttyACM0')

    return r

from Crypto.Cipher import AES

def xor_bytes(a, b):
    return bytes(m ^ n for m, n in zip(a, b))

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

Rcon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]

def xor(a, b):
    res = []
    for i in range(len(a)):
        res.append(a[i]^b[i])
    return res

def shift(s):
    return [s[1], s[2], s[3], s[0]]

def sub(s):
    return [Sbox[s[0]], Sbox[s[1]], Sbox[s[2]], Sbox[s[3]]]

def invert_schedule(key, round):
    """
    K(i-1, 4) = K(i, 3) XOR K(i, 4)
    K(i-1, 3) = K(i, 2) XOR K(i, 3)
    K(i-1, 2) = K(i, 1) XOR K(i, 2)
    K(i-1, 1) = K(i, 1) XOR sub(shift(K(i-1, 4)) XOR RCON(i)
    """

    prev_key = [None] * 4

    prev_key[3] = xor(key[2], key[3])
    prev_key[2] = xor(key[1], key[2])
    prev_key[1] = xor(key[0], key[1])
    prev_key[0] = xor(xor(key[0], sub(shift(prev_key[3]))), [Rcon[round], 0, 0, 0])

    return prev_key

def invert_key(key, round):
    key_u32 = []
    for part in chunks(key, 4):
        key_u32.append(list(part))

    out = invert_schedule(key_u32, round)
    out_bytes = b''
    for n in out:
        out_bytes += bytes(n)

    return out_bytes

def find_round_keys(data):
    for i in range(16, len(data) - 16):
        first_part = data[i-16:i]
        last_part = data[i:i + 16]

        for r in range(0, 15):
            old_key = invert_key(last_part, r)

            if old_key == first_part:
                print(first_part)
                print(last_part)
                print(r)
                return

def main():
    # r = conn()

    # round_keys = b'L\xf7a\xd4\x85I\x9b\xd2\nH\x0b\xab\xf8*<\xd8G9V\xae\x9e`{\x0eb\xf1\x88)&\x8f\xf8\x80B@\xb5\xb4\x12\rO\xcb'
    round_keys = b'noflagonthischan^ flag ^00074c7ac115570d^ time ^0aae86824f2963d5\x00\x00\x00\x00L\xf7a\xd4\x85I\x9b\xd2\nH\x0b\xab\xf8*<\xd8G9V\xae\x9e`{\x0eb\xf1\x88)&\x8f\xf8\x80B@\xb5\xb4\x12\rO\xcbo\xed\xee\x1b\x98\x89J\x82\x13\xe6\x1b\xd3(\xaa1\xb5\x02\x91\xc1Q]\x1d!\x90\t\xfe\x14\xddA\xf0\xf5auW%\xfc\x00\xd0\x8c\xcb\x8c\xb5\xa5e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    find_round_keys(round_keys)
    # last_key = round_keys[-16:]
    # key = last_key

    # for i in range(10, 0, -1):
    #     key = invert_key(key, i)
    #     print(key)


    # leak = b'noflagonthischan^ flag ^00074c7ac115570d^ time ^0aae86824f2963d5\x00\x00\x00\x00L\xf7a\xd4\x85I\x9b\xd2\nH\x0b\xab\xf8*<\xd8G9V\xae\x9e`{\x0eb\xf1\x88)&\x8f\xf8\x80B@\xb5\xb4\x12\rO\xcbo\xed\xee\x1b\x98\x89J\x82\x13\xe6\x1b\xd3(\xaa1\xb5\x02\x91\xc1Q]\x1d!\x90\t\xfe\x14\xddA\xf0\xf5auW%\xfc\x00\xd0\x8c\xcb\x8c\xb5\xa5e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    # expired_checksum = b'\nH\x0b\xab\xf8*<\xd8G9V\xae\x9e`{\x0eb\xf1\x88)'

    with open('expired.sub', 'rb') as f:
        sub = f.read()

    # print(sub)
    pt = bytes([184, 73, 240, 158, 193, 51, 228, 54, 50, 164, 50, 154, 83, 127, 93, 38])
    pt = xor_bytes(sub[-16:], pt)
    # print(pt)

    # expire_packet = bytes.fromhex('020000003a9f43bb7a4c070040000000c485b217ebc0c6b133983c099d10643b36ad95c6ba2371ddcb2de0d8aa221c3948147a5f291fc258eacd0a789420cd5b6ad520df0ede87a920257c03be7c626e7c37da4882a5935bd8421f93a8ca7f426c8bbf3f9d15a07dcfd76b188eed526f9b5d0e567b8a8a2f3206d1124f2a6620')
    # valid_packet = bytes.fromhex('000000000d5715c17a4c070040000000d184f0c59bad57035b91fe81a3ee78a252944486e427312a2163cca7d2406912730344fcdacbc59ff7a6712c2668d5c72424cdd426116cea671cce48728cca0d0b8a1227f729a04bbed2197d07cbf1e948b7bdbda2ce396e0e4c780245e8c66da75387ddae1c30b005897de999714c10')
    # new_packet = valid_packet[:12] + p32(0x200) + valid_packet[16:]

    # print(r.subscribe(sub))

    # # print(r.list())

    # # packet = bytes.fromhex('030000009f63b84c7a4c070040000000a2d1cb383a3b2236e4f7bb30e64b7a4ca66b69a580340cbaebde2700952d17d404d2afa50ccb1dfbe0e03a1feac733b793af5d3ec0c274e988842104389e3b82f7cd4dfdc41d2af341c96cf655b330c9dd972968b7efa5754ee4a219533624a1860583863d645e35b2dd1a52af5c1135')
    # # leaks 0x44 offset into aes context
    # out = r.decode(new_packet)
    # print(out)


    # b = r.subscribe(b'example')
    # a = r.decode(b'example')



if __name__ == "__main__":
    main()
