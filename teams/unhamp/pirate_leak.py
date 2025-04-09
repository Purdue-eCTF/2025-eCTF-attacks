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

    offset_to_sha256 = 128 + 0x10 + 64
    sha256_size = 112

    frame = c0_frames[0].data
    old_len = 64
    new_len = 255
    diff = xor(p8(old_len), p8(new_len))

    frame_body = frame[48:]
    block_index = 2
    block_before_len = frame_body[block_index*16:16*block_index+16]
    offset_in_block = 12
    # offset_in_block = 0
    new_block = block_before_len[:offset_in_block] + xor(p8(block_before_len[offset_in_block]), diff) + block_before_len[offset_in_block + 1:]
    # new_block = block_before_len
    new_body = frame_body[:block_index*16] + new_block + frame_body[16*block_index+16:]

    new_frame = frame[32:48] + new_body

    result = decode(new_frame)
    print(p32(attacker_id) in result)
    print(len(result))
    print(result.hex())
    print(result[67:])
    print()
    print()

    # for i in range(64, 256):
    #     key = result[i:i+32]
    #     c = AES.new(key, AES.MODE_CBC, iv = frame[32:48])
    #     result = c.decrypt(frame[48:])
    #     if b'noflagonthischan' in result:
    #         print(i)
    #         print(key)
    key = result[67+16:67+64+16]
    print(key.hex())
    # c = AES.new(key, AES.MODE_CBC, iv = frame[32:48])
    # result = c.decrypt(frame[48:])
    # print(result)



    # print(r.list())
    # b = r.subscribe(b'example')
    # a = r.decode(b'example')



if __name__ == "__main__":
    main()
