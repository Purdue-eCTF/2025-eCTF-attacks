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

    attacker_id = 0x9fcdb194
    pirated_id = 0x8825a75a
    pesky_id = 0x7b1186ce

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

    sub_start = 1551157932102814
    sub_end = 1607133144206408

    time_pt = p64(sub_end) + p64(sub_start)
    block_pt = xor(c1_valid[:16], time_pt)
    block_ct = c1_valid[16:32]

    frame = c1_frames[0].data
    frame_header = frame[:32]

    playback_part = playback_frames[0].data[:48]
    forge = frame[:48] + playback_part
    

    # r.subscribe(forge)
    # print(r.decode(forge))
    print(r.list())

    # print(r.decode(c1_frames[-1].data))
    # print(r.decode(c0_frames[0].data))

    # print(r.list())
    # b = r.subscribe(b'example')
    # a = r.decode(b'example')



if __name__ == "__main__":
    main()
