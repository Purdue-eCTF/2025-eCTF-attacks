#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf
from ectf25_attack.utils import load_frames, Frame, filter_channel
from Crypto.Cipher import AES

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

def hmac_leak_to_hmac(data):
    out = bytearray()
    for i in range(8):
        out.append(data[4*i+3])
        out.append(data[4*i+2])
        out.append(data[4*i+1])
        out.append(data[4*i+0])
    return bytes(out)

def main():
    r = conn()

    # forge mac and decode
    def decode(body):
        try:
            return r.decode(b'\0' * 32 + body)
        except Exception as e:
            value = repr(e)
            hex_value = value.split('Signature: ')[1][:64]
            mac = hmac_leak_to_hmac(bytes.fromhex(hex_value))
            return r.decode(mac + body)

    attacker_id = 0xfc045cdc
    pirated_id = 0x6e9c95e8
    pesky_id = 0x53986594

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

    # r.subscribe(c1_valid)
    # r.subscribe(c2_expired)
    # print(r.list())
    frame = c0_frames[0].data
    main_key = b'\x1e\xbe\xe5[\x175\x9e\xeds\xdb\x18\x8f\xb2\xf6YV\x8d\n\ry8\x92\xa1bxK\xc8\xa6\x13Y\x89\x00'
    c = AES.new(main_key, AES.MODE_CBC, iv = frame[32:48])
    result = c.decrypt(frame[48:])
    print(result)



    # print(r.list())
    # b = r.subscribe(b'example')
    # a = r.decode(b'example')



if __name__ == "__main__":
    main()
