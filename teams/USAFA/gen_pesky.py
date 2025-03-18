import socket
import argparse
import json
from ectf25_attack.utils import load_frames, save_frames, Frame, filter_channel
from pwn import *


def main():
    frames = load_frames('frames.json')

    c0_frames = filter_channel(frames, 1)
    frame1 = c0_frames[0]
    print(frame1.data.hex())
    frame2 = c0_frames[1]

    timestamp = frame2.timestamp + 1
    frame1_bad = frame1.with_data(p64(timestamp) + frame1.data[8:])

    out = [frame2, frame1_bad]

    save_frames('pesky_frames.json', out)

if __name__ == '__main__':
    main()
