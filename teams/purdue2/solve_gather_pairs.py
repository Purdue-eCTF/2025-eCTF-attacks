#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf
from ectf25_attack.utils import load_frames, Frame, filter_channel
from dataclasses import dataclass
import json

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

# Represents a plaintext ciphertext pair
@dataclass
class Pair:
    pt: bytes
    ct: bytes

def check_no_dups(pairs):
    pt_set = set(pair.pt for pair in pairs)
    ct_set = set(pair.ct for pair in pairs)
    assert len(pt_set) == len(pairs)
    assert len(ct_set) == len(pairs)

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
    # print(len(c1_frames))
    # eexpired frames
    c2_frames = filter_channel(frames, 2)
    # pirated frames
    c3_frames = filter_channel(frames, 3)
    # no subscription frames
    c4_frames = filter_channel(frames, 4)

    frame_counter = 0
    # frame haders used for querying processor, need to do them in order to avoid timestamp issue
    frame_headers = [frame.data[:32] for frame in c1_frames]

    def decrypt_body(body):
        nonlocal frame_counter
        assert len(body) % 16 == 0
        # use each header in a monotonicly increasing order
        header = frame_headers[frame_counter]
        frame_counter += 1

        padding = (64 - len(body)) * b'\0'
        frame = header + body + padding

        return r.decode(frame)

    # obtains dec(inner.ct ^ outer.pt)
    # returns it as a pair
    def oracle1(outer: Pair, inner: Pair):
        message = b'\0' * 16 + xor(inner.ct, outer.pt) + outer.ct
        # 0 || ict ^ opt      || oct
        # ? || dec(ict ^ opt) || ict
        # ? || ?              || ipt ^ dec(ict ^ opt)

        result = decrypt_body(message)
        dec_ict_opt = xor(result[32:48], inner.pt)

        return Pair(ct = xor(inner.ct, outer.pt), pt = dec_ict_opt)

    # obtains dec_inner(outer1.pt ^ outer2.ct)
    # returns it as a pair
    def oracle2(outer1: Pair, outer2: Pair):
        message = outer2.pt + outer2.ct + outer1.ct
        # opt2 || oct2 || oct1
        # ?    || 0    || opt1 ^ oct2
        # ?    || ?    || dec(opt1 ^ oct2)

        result = decrypt_body(message)
        return Pair(ct = xor(outer1.pt, outer2.ct), pt = result[32:48])

    try:
        with open('outer_pairs.json', 'r') as f:
            data = json.loads(f.read())
            known_outer = [Pair(pt = bytes.fromhex(elem["pt"]), ct = bytes.fromhex(elem["ct"])) for elem in data]
    except Exception as e:
        print(e)

        # suscribe to channel 1 (use channel 1 header frames since there are more of them to capture)
        r.subscribe(c1_valid)

        print(r.list())

        # find a known outer plaintext
        # these are channel 1 time values
        sub_start = 1551157932102814
        sub_end = 1607133144206408

        time_pt = p64(sub_end) + p64(sub_start)
        block_pt = xor(c1_valid[:16], time_pt)
        block_ct = c1_valid[16:32]

        known_outer = [Pair(pt = block_pt, ct = block_ct)]

    # find an initial known inner pladintext
    # use other sub so there is no relation which causes issues when generating other known outer pairs
    sub_start = 1429884800299345
    sub_end = 1511941592364455

    time_pt = p64(sub_end) + p64(sub_start)
    block_pt = xor(c2_expired[:16], time_pt)
    block_ct = c2_expired[16:32]

    body = b'\0' * 16 + block_ct + block_ct
    #     0 || oct || oct
    #     ? || opt || ict = opt ^ oct
    #     ? || ?   || ipt ^ opt
    result = decrypt_body(body)
    # compute ict
    inner_ct = xor(block_ct, block_pt)

    message_part = result[32:48]
    # cancle out opt
    inner_pt = xor(message_part, block_pt)

    known_inner = [Pair(pt = inner_pt, ct = inner_ct)]


    # generate a lot of known outer plaintexts ciphertext pairs
    for _ in range(len(frame_headers) - frame_counter):
        last_outer_pair = known_outer[-1]

        # obtains dec(inner.ct ^ outer.pt)
        # new plaintext in next iteration will have gone through aes, so we can make a chain of random pairs
        known_outer.append(oracle1(last_outer_pair, known_inner[0]))

    check_no_dups(known_outer)
    print(known_outer)
    print(known_inner)
    known_json = json.dumps([{"ct": pair.ct.hex(), "pt": pair.pt.hex()} for pair in known_outer])
    with open('outer_pairs.json', 'w') as f:
        f.write(known_json)
    print(json.dumps([{"ct": pair.ct.hex(), "pt": pair.pt.hex()} for pair in known_inner]))
    print('sub last part')
    print(c2_expired[32:48])
    print('known pairs count')
    print(len(known_outer))



if __name__ == "__main__":
    main()
