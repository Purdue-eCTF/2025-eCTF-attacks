#!/usr/bin/env python3
from ectf25.utils.decoder import DecoderIntf
# from Crypto.Cipher import AES
# import struct
import sys


# def gen_packet():
#     key = b's;\x85\x1c\x03\x82\xd9\xf2,X\x8a-\x0eS++'
#     cipher = AES.new(key=key, mode=AES.MODE_ECB)
#     pkt = b"this is a random frame that shouldn't have been send ".ljust(
#         64, b"a")
#     frame = cipher.encrypt(pkt)
#     frame_size = len(frame)
#     header = struct.pack("<IQI", 0, 123, frame_size)

#     full_packet = header + frame

#     # Pad the full packet to a multiple of 16 bytes
#     if len(full_packet) % 16 != 0:
#         padding_length = 16 - (len(full_packet) % 16)
#         full_packet += b"\x80" + b"\x00" * (padding_length - 1)

#     print(cipher.encrypt(full_packet).hex())


def conn():
    r = DecoderIntf(sys.argv[1], timeout=5, write_timeout=5)
    return r


def main():
    r = conn()
    frame = {"channel": 0, "timestamp": 123,
             "encoded": "a937ae195388f24cddcea2ec67aa2d9ee8691d3344f9167e899f40273b18fb65058c27e57c609a01f4c4c8ef37b4f82d019770cbfaf695edce8c13b82cbddf8b73115e096567de1e412f0c0da43bd95e"}
    print(r.decode(bytes.fromhex(frame["encoded"])))


if __name__ == "__main__":
    # gen_packet()
    main()
