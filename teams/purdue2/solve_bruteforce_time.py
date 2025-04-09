#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf
from ectf25_attack.utils import load_frames, Frame, filter_channel
from dataclasses import dataclass
import json

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

# Represents a plaintext ciphertext pair
@dataclass
class Pair:
    pt: bytes
    ct: bytes

def check_no_dups(pairs):
    pt_set = set(pair.pt for pair in pairs)
    ct_set = set(pair.ct for pair in pairs)
    assert len(pt_set) == len(pairs)
    assert len(ct_set) == len(pairs)

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
    # print(len(c1_frames))
    # eexpired frames
    c2_frames = filter_channel(frames, 2)
    # pirated frames
    c3_frames = filter_channel(frames, 3)
    # no subscription frames
    c4_frames = filter_channel(frames, 4)

    with open('outer_pairs.json', 'r') as f:
        data = json.loads(f.read())
        outer_pairs = [Pair(pt = bytes.fromhex(elem['pt']), ct = bytes.fromhex(elem['ct'])) for elem in data]

    # pt_ct_pair = {'ct': b'c\x9c\x11\x85\x8b(~yJ=\xf3\xb0\x0f\x0b\xfd9', 'pt': b'Nuz\xc48bj\x1d\xad\x0bY\xa8_\x90\x8d\xbc'}

    last_block_pt = b'Nuz\xc48bj\x1d\xad\x0bY\xa8_\x90\x8d\xbc'
    device_id_inner_ct = xor(last_block_pt, c2_expired[16:32])

    frame = c2_frames[0]
    print(r.decode(frame.data))
    return

    for pair in outer_pairs:
        prev_block = xor(pair.pt, device_id_inner_ct)
        fake_sub = c2_expired[:16] + prev_block + pair.ct
        try:
            r.subscribe(fake_sub)
        except:
            continue

        time_start, time_end = [(time_start, time_end) for channel, time_start, time_end in r.list() if channel == 2][0]
        print(time_start)
        print(time_end)
        if frame.timestamp >= time_start and frame.timestamp <= time_end:
            print('found valid sub')
            print(pair)
            print(r.decode(frame.data))

    # print(c1_valid[32:])

if __name__ == '__main__':
    main()
