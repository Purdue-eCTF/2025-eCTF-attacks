#!/usr/bin/env python3

from ectf25.utils.decoder import DecoderIntf
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

    recorded = bytes.fromhex(
        "02000000c060edd744e3dee5aa5e32a4aa59c7e480d8e6206414d5e27b7fcc4c925fb5dfdc3d180f3b67d53674cf5cb7ed57670a2a1b64b6ac04a1c27c89b60a5cb9b66fafc03d48907299875f96ebb8aee9470ad3d35e7547933a22f3aaae4b511911fc")

    iv = recorded[4:20]
    timestamp = struct.pack("<Q", 1959708314922475)+b"\x00"*8
    new_timestamp = struct.pack("<Q", 1833655655548593)+b"\x00"*8

    new_iv = xor(xor(iv, timestamp), new_timestamp)
    print(len(new_iv))

    print(
        r.decode(recorded[:4]+new_iv+recorded[20:]))


if __name__ == "__main__":
    main()
