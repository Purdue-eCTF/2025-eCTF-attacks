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

    attacker_id = 0x42f52b16
    pirated_id = 0x6f698f63
    pesky_id = 0x783d7dd0

    c1_valid = read_if_exists('c1_valid.sub')
    c2_expired = read_if_exists('c2_expired.sub')
    c3_pirated = read_if_exists('c3_pirated.sub')
    frames = load_frames('frames.json')
    playback_frames = load_frames('playback_frames.json')

    # emergency
    c0_frames = filter_channel(frames, 0)
    # valid, with recorded frames
    c1_frames = filter_channel(frames, 1)
    # eexpired frames
    c2_frames = filter_channel(frames, 2)
    # pirated frames
    c3_frames = filter_channel(frames, 3)
    # no subscription frames
    c4_frames = filter_channel(frames, 4)

    # c2_valid = p32(2) + c1_valid[4:]
    # c3_valid = p32(3) + c1_valid[4:]
    # c4_valid = p32(4) + c1_valid[4:]
    c3_iv = c3_pirated[4:20]
    new_iv = xor(xor(p32(attacker_id), p32(pirated_id)), c3_iv[:4]) + c3_iv[4:]
    c3_valid = p32(3) + new_iv + c3_pirated[20:]

    # r.subscribe(c2_valid)
    r.subscribe(c3_valid)
    # r.subscribe(c4_valid)

    # print(r.decode(c2_frames[0].data))
    print(r.decode(c3_frames[0].data))
    # print(r.decode(c4_frames[0].data))

    print(r.list())
    b = r.subscribe(b'example')
    a = r.decode(b'example')



if __name__ == "__main__":
    main()
