#!/usr/bin/env python3

import sys
from decoder import DecoderIntf, DecoderError
import hashlib
import struct


def conn():
    r = DecoderIntf('/dev/ttyACM0')

    return r


def read_if_exists(name):
    try:
        with open(name, 'rb') as f:
            return f.read()
    except:
        return None


def xor(a, b):
    return bytes(m ^ n for m, n in zip(a, b))


def main():
    r = conn()

    expired_sub = bytes.fromhex(
        '99b2e3c5679f62d7d17ccefa7be24f7baf6bc365d4069e039f7b98673ad1a1e51cda83605c12335681d9db3734fca31fcbaf378bc9ecc26baa33e5a23800000045a802607e8f2896ae4de02095ce80cad481cf03cd914312fc8060f6e885a9475479d2441399f73df544a020c364a8c30f6a5f185927dba3')
    pirated_sub = bytes.fromhex(
        'e23e29378af08f4c7f3c35de03484d1130ee09db3893b8c3e617f5f8c074d7c4a84a1a6daec634dad54448acd748f7b1b71a886a11448b5a936037e938000000acd9b167b4dde623f03031b178621515c8d03b8c69286b20b65ab1a49706d8b97fa7018b48684e7a6bf35575b9c2ded04d31fa8830972bc3')
    own_sub = bytes.fromhex('301e05b27ac55861b0fc4ac1fab7d263797ae70e395bd6aa293712ff2d7e034e846c6ded54d43bf109fa02fcdea061c0eec82b90254546078b366b803800000040058a1a2e86e5ee33b7fc75d29fc4df7b4577f4afb4ee5346891a3b2a182d484c42fbc855bd907d19d2820502288ab1ac8711922ac37c1e')

    expired_sub = pirated_sub

    tag = expired_sub[:16]
    sha = expired_sub[16:48]
    nonce = expired_sub[48:60]
    l = expired_sub[60:64]

    pt = b""
    # pt = b'\xb8qr\x98\x9d\xef\x07\xd4\x96!\xcd\xb6\x97\x03\xca\x04HeI\xc9\x1b\x10\x8c\x11'
    ct = expired_sub[64:]

    for i in range(len(pt)+1, len(ct)+1):
        for c in range(256):
            target_message = struct.pack(
                "<IQQQIIQ", 0, 0, 0, 0, 0x40, 0x0, i*256) + b"\x00"*0x40
            guess_sha = hashlib.sha256(target_message[:i]).digest()
            packet = struct.pack("<16s32s12sI", tag,
                                 guess_sha, nonce, i) + xor(ct[:i], xor(pt + bytes([c]), target_message[:i]))
            try:
                r.decode(packet)
                pt += bytes([c])
                print(pt)
                sys.stdout.flush()
                break
            except DecoderError as e:
                if 'Bad Hash Data' in repr(e):
                    continue
                pt += bytes([c])
                print(pt)
                sys.stdout.flush()
                break
        print(pt)
        sys.stdout.flush()
    print(pt)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
