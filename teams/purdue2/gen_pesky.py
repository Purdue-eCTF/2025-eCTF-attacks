import socket
import argparse
import json
from ectf25_attack.utils import load_frames, save_frames, Frame, filter_channel, repeated_frame, per_channel_check, default_pesky

def xor(a, b):
    return bytes(m ^ n for m, n in zip(a, b))

def main():
    attacker_id = 0x9fcdb194
    pirated_id = 0x8825a75a
    pesky_id = 0x7b1186ce

    frames = load_frames('frames.json')

    c0_frames = filter_channel(frames, 0)
    c1_frames = filter_channel(frames, 1)

    # Uncomment relavant attack, or write one from scratch
    frame = c0_frames[0]
    frame.data = frame.data[:-16] + b'a' * 16
    print(frame)
    # output = default_pesky(frames)
    # output = repeated_frame(frames)
    # output = per_channel_check(frames)

    save_frames('pesky_frames.json', [frame])

if __name__ == '__main__':
    main()
