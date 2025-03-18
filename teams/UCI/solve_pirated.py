#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf

context.arch = 'thumb'

def conn():
    r = DecoderIntf('/dev/ttyACM0')

    return r

def xor(a, b):
    return bytes(m ^ n for m, n in zip(a, b))

def main():
    r = conn()

    real_id = 0x1b664ce9
    fake_id = 0xaf1eabd7

    with open('pirated.sub', 'rb') as f:
        pirate_sub = f.read()

    iv = pirate_sub[-16:]

    iv_xor = xor(p32(real_id), p32(fake_id))
    iv_xor = bytes([iv_xor[0], 0, iv_xor[1], 0, iv_xor[2], 0, iv_xor[3], 0]) + b'\0' * 8
    new_iv = xor(iv, iv_xor)

    print(r.subscribe(pirate_sub[:-16] + new_iv))

    print(r.list())

    packet = bytes.fromhex('030000009f63b84c7a4c070040000000a2d1cb383a3b2236e4f7bb30e64b7a4ca66b69a580340cbaebde2700952d17d404d2afa50ccb1dfbe0e03a1feac733b793af5d3ec0c274e988842104389e3b82f7cd4dfdc41d2af341c96cf655b330c9dd972968b7efa5754ee4a219533624a1860583863d645e35b2dd1a52af5c1135')
    print(r.decode(packet))

    # b = r.subscribe(b'example')
    # a = r.decode(b'example')



if __name__ == "__main__":
    main()
