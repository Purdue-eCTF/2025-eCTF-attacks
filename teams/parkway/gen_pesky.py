import socket
import argparse
import json
from ectf25_attack.utils import load_frames, save_frames, Frame, filter_channel, repeated_frame, per_channel_check, default_pesky

def xor(a, b):
    return bytes(m ^ n for m, n in zip(a, b))

def main():
    attacker_id = 0x5b2f9687
    pirated_id = 0x9ad47843
    pesky_id = 0xc9a7b46b

    frames = load_frames('frames.json')

    c0_frames = filter_channel(frames, 0)
    c1_frames = filter_channel(frames, 1)

    # Uncomment relavant attack, or write one from scratch
    output = default_pesky(frames)
    # output = repeated_frame(frames)
    # output = per_channel_check(frames)

    save_frames('pesky_frames.json', output)

if __name__ == '__main__':
    main()
