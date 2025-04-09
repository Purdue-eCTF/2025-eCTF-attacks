import socket
import argparse
import json
from ectf25_attack.utils import load_frames, save_frames, Frame, filter_channel, repeated_frame, per_channel_check, default_pesky
from struct import pack

def xor(a, b):
    return bytes(m ^ n for m, n in zip(a, b))

def main():
    attacker_id = 0x1a867aab
    pirated_id = 0x92167cd7
    pesky_id = 0x4ceb220a

    frames = load_frames('frames.json')

    c0_frames = filter_channel(frames, 0)
    c1_frames = filter_channel(frames, 1)

    # Uncomment relavant attack, or write one from scratch
    # output = default_pesky(frames)
    channel = 0
    timestamp = 10000
    frame = b'a' * 64
    msg = pack("<IQH64s", channel, timestamp, len(frame), frame)
    output = [Frame(channel, timestamp, pack('<I', channel) + b'a' * 12 + msg)]
    # output = repeated_frame(frames)
    # output = per_channel_check(frames)

    save_frames('pesky_frames.json', output)

if __name__ == '__main__':
    main()
