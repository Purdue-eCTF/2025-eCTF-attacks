#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf
from ectf25_attack.utils import load_frames, Frame, filter_channel

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

    r.subscribe(c1_valid)
    r.subscribe(c2_expired)
    print(r.list())

    c1_start, c1_end = (1573206130594816, 1608686588997622)
    c2_start, c2_end = (1467350296527344, 1539299091523241)

    pframe = playback_frames[0]
    pframe_iv = pframe.data[32:48]
    fake_iv = pframe_iv[:4] + xor(pframe_iv[4:12], xor(p64(pframe.timestamp), p64(c1_start + 1))) + pframe_iv[12:]
    # fake_iv = pframe_iv[:4] + xor(pframe_iv[4:12], ) + pframe_iv[12:]
    # hmac = hmac_leak_to_hmac(bytes.fromhex('8a7aec0fa08130a41dd751e6e79df491658b4dfead78be2522e87e8585e7b2d3'))
    hmac = hmac_leak_to_hmac(bytes.fromhex('6f0857a79ae07befffceb10547b5996fe508d9b82ec51310ef1aea432a14a48b'))
    fake_frame = hmac + fake_iv + pframe.data[48:]

    print(r.decode(fake_frame))

    cframe = c2_frames[0]
    cframe_iv = cframe.data[32:48]
    fake_iv = cframe_iv[:4] + xor(cframe_iv[4:12], xor(p64(cframe.timestamp), p64(c2_start + 1))) + cframe_iv[12:]
    # fake_iv = pframe_iv[:4] + xor(pframe_iv[4:12], ) + pframe_iv[12:]
    # hmac = hmac_leak_to_hmac(bytes.fromhex('8a7aec0fa08130a41dd751e6e79df491658b4dfead78be2522e87e8585e7b2d3'))
    hmac = hmac_leak_to_hmac(bytes.fromhex('ff7af90820736b0dba004d019924fa2aa723ab812cf035c8e8298baffd8b4d97'))
    fake_frame = hmac + fake_iv + cframe.data[48:]

    print(r.decode(fake_frame))

    # print(r.list())
    # b = r.subscribe(b'example')
    # a = r.decode(b'example')



if __name__ == "__main__":
    main()
