#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf
from ectf25_attack.utils import load_frames, Frame, filter_channel
import hashlib

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

    # print('sub')
    # print(c1_valid.hex())
    # print(f'{len(c1_valid) = }')

    # print('c0 frame')
    # print(c0_frames[0].data.hex())
    # print(f'{len(c0_frames[0].data) = }')

    # print('c1 frame')
    # print(c1_frames[0].data.hex())
    # print(f'{len(c1_frames[0].data) = }')

    r.subscribe(c1_valid)

    print(c1_frames[1].timestamp)

    print(c0_frames[0])
    print(c0_frames[1])

    pt = b'noflagonthischan'
    keystream = xor(c0_frames[0].data[12:12+len(pt)], pt)

    for message, frame in [('recording', playback_frames), ('expired', c2_frames), ('pirate', c3_frames), ('nosub', c4_frames)]:
        flag = xor(frame[0].data[12:12+len(pt)], keystream)
        print(f'flag for {message}: {flag}')

    pt = r.decode(c0_frames[0].data)
    header = p32(0) + p64(c0_frames[0].timestamp)
    print(f'c0 plaintext: {header + pt}')


    # forge = b'\xf2\xf3\x8aq\xa1\x93r\xe3\xfa%<i\x9d\xed\xf9d-v\x9d[\xd5\xbe\xc08\x9d\x12\xe4\x03\xb6\xd7\x90\xd9\xb6\xe7\xf7\x0eX}\xf2I?\x83\xa3C\x06\xa4\xa2\xf5\xd2\xca\x80_\x1ce\xb1\n\xe28_\xba.\x19\xdei\xeb\x0b\xdb\xbfTW\xea\xbc\xccO\x96\xa1\xfeJ\x83B|\x91{\x1eh\x88s\x17>\xd9\xb34'
    forges = [b"\xf3\xf3\x8aq\xad\xb9\xd1\xe3\xfa%<i\x9d\xed\xf9d-v\x9d[\xd5\xbe\xc08\x9d\x12\xe4\x03\xb6\xd7\x90\xd9\xb6\xe7\xf7\x0eX}\xf2I?\x83\xa3C\x06\xa4\xa2\xf5\xd2\xca\x80_\x1ce\xb1\n\xe28_\xba.\x19\xdei\xeb\x0b\xdb\xbfTW\xea\xbc\xccO\x96\xa1\xb1\x19O\x18\xdc\xd2pS'\x06a\xf8\x911\x80\x05", b"\xf3\xf3\x8aq\xad\xb9\xd1\xe3\xfa%<i\x9d\xed\xf9d-v\x9d[\xd5\xbe\xc08\x9d\x12\xe4\x03\xb6\xd7\x90\xd9\xb6\xe7\xf7\x0eX}\xf2I?\x83\xa3C\x06\xa4\xa2\xf5\xd2\xca\x80_\x1ce\xb1\n\xe28_\xba.\x19\xdei\xeb\x0b\xdb\xbfTW\xea\xbc\xccO\x96\xa1\x8f\x94\xc3\xf0\xa7\xc0\x0c\x0b\xf1\xe1\xfbu'ii\xff", b'\xf3\xf3\x8aq\xad\xb9\xd1\xe3\xfa%<i\x9d\xed\xf9d-v\x9d[\xd5\xbe\xc08\x9d\x12\xe4\x03\xb6\xd7\x90\xd9\xb6\xe7\xf7\x0eX}\xf2I?\x83\xa3C\x06\xa4\xa2\xf5\xd2\xca\x80_\x1ce\xb1\n\xe28_\xba.\x19\xdei\xeb\x0b\xdb\xbfTW\xea\xbc\xccO\x96\xa1\xc7\xdb\x98\\j\x0f\xbd\xfa\x99\x0bQBQ\x7f\xab\x0f', b'\xf3\xf3\x8aq\xad\xb9\xd1\xe3\xfa%<i\x9d\xed\xf9d-v\x9d[\xd5\xbe\xc08\x9d\x12\xe4\x03\xb6\xd7\x90\xd9\xb6\xe7\xf7\x0eX}\xf2I?\x83\xa3C\x06\xa4\xa2\xf5\xd2\xca\x80_\x1ce\xb1\n\xe28_\xba.\x19\xdei\xeb\x0b\xdb\xbfTW\xea\xbc\xccO\x96\xa1At6\xcae\x1b\\\xa2S\x94\xb8?H\xf9\x80*']
    for forge in forges:
        try:
            print(r.decode(forge))
            print(forge)
            break
        except:
            continue


    # print(r.decode(forge))


    # print(c1_frames[1].data.hex())
    # print(c1_frames[2].data.hex())
    
    # frame = c1_frames[1].data[12:12+64]
    # mac = c1_frames[1].data[12+64:]
    # print(len(mac))
    # pt = b'noflagonthischan^ flag ^000745869d2c3fbc^ time ^d928a8df3a396b4d'
    # header = p32(1) + p64(c1_frames[1].timestamp)
    # pt = header + pt
    # assert len(pt) + 16 == len(c1_frames[1].data)
    # print(pt)
    # h = hashlib.md5(pt).digest()
    # print(mac)
    # print(h)
    # keystream = xor(pt, frame)
    # decrypt = xor(playback_frames[0].data[12:12+64], keystream)
    # print(decrypt)
    # ct2 = xor(c2_frames[0].data, pt)

    # test_forge = bytes.fromhex('f3f38a710d75d468fb253c699eb8a0322d20980b80ef943f9a40b101899697d4b6e1b631092ca31f6ad7fa1556f3fbf5d792d00e2324a402ee3c1e85761d8a69ba088cec0307bfef951ec2f62d8c23e794eddd0f31a91c8ef1c7138f')
    # print(r.decode(test_forge))

    # frame = frame[:-1] + b'a'
    # r.decode(c1_frames[1].data)
    # print(r.decode(c1_frames[-1].data))
    # print(r.decode(c0_frames[0].data))

    # print(r.list())
    # b = r.subscribe(b'example')
    # a = r.decode(b'example')



if __name__ == "__main__":
    main()
