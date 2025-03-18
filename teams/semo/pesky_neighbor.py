#!/usr/bin/env python3
from ectf25.utils.decoder import DecoderIntf
# from Crypto.Cipher import AES
import sys

# key = bytes([0x24, 0xf6, 0x75, 0x43, 0x64, 0xb9, 0x54, 0xcf, 0xb3, 0x36, 0x71, 0xc8, 0x31, 0xda, 0x58,
#              0x2e, 0xdb, 0x88, 0xb9, 0x42, 0x44, 0x23, 0x57, 0xd9, 0xc9, 0x5a, 0xe9, 0x4e, 0x9f, 0x8f, 0xe2, 0x0d])

# iv = bytes([0xc6, 0xd3, 0x0c, 0x12, 0x4f, 0xbe, 0x47, 0xe8,
#             0x6a, 0x02, 0xfc, 0x2a, 0x64, 0xb2, 0x30, 0xbf])

# def gen_packet():
#     cipher = AES.new(key=key, iv=iv, mode=AES.MODE_CBC)
#     pkt = b'\x01\x00\x00\x00\x00\x00\x00\x00\x1a\xeb\x1f\x91\x03\xb9\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00pwnedgonthischan^ flag ^0006b903911feb1a^ time ^c43d8e7452de706e'
#     frame = cipher.encrypt(pkt)
#     print(frame)


def conn():
    r = DecoderIntf(sys.argv[1], timeout=5, write_timeout=5)
    return r


def main():
    r = conn()
    frame = b'\xec\xcf\xefE\xb3\x7f\xb2O\xd3$\xdb,\x8d\x80\x1d\xfd\xff\x95\xb4\x1dw\x84\x9b\x11\xf5f\xf1\xf0PK[\x9d\xd3\xb37[\xd4hj\xff)\x9d \xcb\x91\xdc*3\x8f\xd0\x04(\x9a\x94z{8\xe2\xf9x\x00N&\x83h\xfa\xb2\xd7^\xb0\xef8\x96\x03\xec\xd5\xb1j\xafM{f\x9ei\x84\xe5\x8c.\xb1\xd5\xaf\xee\xcc\xd9\xd0\xc6'
    print(r.decode(frame))


if __name__ == "__main__":
    main()
