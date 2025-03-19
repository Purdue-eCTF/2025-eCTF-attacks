#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf
from ectf25_attack.utils import load_frames, Frame, filter_channel

context.arch = 'thumb'

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

    c1_valid = read_if_exists('c1_valid.sub')
    c2_expired = read_if_exists('c2_expired.sub')
    c3_pirated = read_if_exists('c3_pirated.sub')
    frames = load_frames('frames.json')
    frame = filter_channel(frames, 3)[0]

    pirate_id = 0x30a101ed
    decoder_id = 0xdb5d7a03

    n = 0xf58352a

    diff = xor(p32(n), p32(decoder_id))

    # diff = xor(p32(pirate_id), p32(decoder_id))
    # n = p32(0xe4a44ec4)
    # diff = xor(n, p32(decoder_id))
    iv = c3_pirated[:16]
    new_iv = xor(iv[:4], diff) + iv[4:]
    fake_sub = new_iv + c3_pirated[16:]

    print(r.list())
    b = r.subscribe(fake_sub)
    print(r.list())
    a = r.decode(frame)



if __name__ == "__main__":
    main()
