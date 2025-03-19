import socket
import argparse
import json
from ectf25_attack.utils import load_frames, save_frames, Frame, filter_channel, repeated_frame, per_channel_check

def main():
    frames = load_frames('frames.json')

    c0_frames = filter_channel(frames, 0)
    c1_frames = filter_channel(frames, 1)

    frame = c0_frames[0]
    frame.data = frame.data[:48] + b'aa' + frame.data[50:]
    output = [frame]

    # Uncomment relavant attack, or write one from scratch
    # output = []
    # output = repeated_frame(frames)
    # output = per_channel_check(frames)

    save_frames('pesky_frames.json', output)

if __name__ == '__main__':
    main()
