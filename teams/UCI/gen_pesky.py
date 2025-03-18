import socket
import argparse
import json
from ectf25_attack.utils import load_frames, save_frames, Frame, filter_channel

def main():
    frames = load_frames('frames.json')

    c0_frames = filter_channel(frames, 0)
    frame = c0_frames[0]
    frame.data = frame.data[:-32] + b'a' * 32

    save_frames('pesky_frames.json', [frame])

if __name__ == '__main__':
    main()
