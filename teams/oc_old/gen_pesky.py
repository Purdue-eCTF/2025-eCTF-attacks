import socket
import argparse
import json
from ectf25_attack.utils import load_frames, save_frames, Frame, filter_channel, repeated_frame, per_channel_check, default_pesky

def xor(a, b):
    return bytes(m ^ n for m, n in zip(a, b))

def main():
    attacker_id = 0xc2c87336
    pirated_id = 0xcf77d764
    pesky_id = 0xba4a575b

    frames = load_frames('frames.json')

    c0_frames = filter_channel(frames, 0)
    c1_frames = filter_channel(frames, 1)

    # Uncomment relavant attack, or write one from scratch
    # output = default_pesky(frames)
    # forge = b'\xf2\xf3\x8aq\xa1\x93r\xe3\xfa%<i\x9d\xed\xf9d-v\x9d[\xd5\xbe\xc08\x9d\x12\xe4\x03\xb6\xd7\x90\xd9\xb6\xe7\xf7\x0eX}\xf2I?\x83\xa3C\x06\xa4\xa2\xf5\xd2\xca\x80_\x1ce\xb1\n\xe28_\xba.\x19\xdei\xeb\x0b\xdb\xbfTW\xea\xbc\xccO\x96\xa1\xfeJ\x83B|\x91{\x1eh\x88s\x17>\xd9\xb34'
    forge = b"\xf3\xf3\x8aq\xad\xb9\xd1\xe3\xfa%<i\x9d\xed\xf9d-v\x9d[\xd5\xbe\xc08\x9d\x12\xe4\x03\xb6\xd7\x90\xd9\xb6\xe7\xf7\x0eX}\xf2I?\x83\xa3C\x06\xa4\xa2\xf5\xd2\xca\x80_\x1ce\xb1\n\xe28_\xba.\x19\xdei\xeb\x0b\xdb\xbfTW\xea\xbc\xccO\x96\xa1\xb1\x19O\x18\xdc\xd2pS'\x06a\xf8\x911\x80\x05"
    output = [Frame(data = forge, timestamp = 2046769301831612, channel = 1)]
    # output = repeated_frame(frames)
    # output = per_channel_check(frames)

    save_frames('pesky_frames.json', output)

if __name__ == '__main__':
    main()
