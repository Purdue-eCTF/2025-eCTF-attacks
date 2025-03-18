import socket
import argparse
import json
from ectf25_attack.utils import load_frames, save_frames, Frame, filter_channel

def main():
    frames = load_frames('frames.json')

    frame0 = filter_channel(frames, 0)[0]
    frame = filter_channel(frames, 0)[1]

    frame.data = frame.data[:32] + b'a' * 48

    save_frames('pesky_frames.json', [frame0, frame])

if __name__ == '__main__':
    main()
