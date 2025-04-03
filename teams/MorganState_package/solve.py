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

# def get_sub_ct_nonce(sub):
#     return sub[]
    

def main():
    r = conn()

    attacker_id = 0xf870d9c5
    pirated_id = 0x36e83ffe
    pesky_id = 0x86590a3

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

    c1_pt = b'\xc5\xd9p\xf8S\xa8\x07\xa8\xbfQ\x06\x00\x0e \xbfy\xb0y\x06\x00\x01\x00\x00\x00\xa8\xe9\xa3\tv9\xcf\xd9.OK\xee\x94tX\x88Q\x9b_V\x83\xfb\xe4\xeb8\xc7,\xeei%\x180'
    c2_pt = b'\xc5\xd9p\xf8\xa6\xc8-"F\xe3\x05\x00\xac\x80\xaa\xee\t*\x06\x00\x02\x00\x00\x00P_\xdf\x0b\xc0!\xdbF\xa6\'\x8e\xdb0\xa3\xda2\xcd-\ne\xd3\xfa\xd4\x9ei\x1e\xa7Eh\xb4*C'
    c3_pt = b'\xfe?\xe86\xe7\\|\x08(R\x06\x00\xf3p\xf1Q{\x80\x06\x00\x03\x00\x00\x00\x8a\xcd\x16\xd4\x1d\xd2)\xe9T^[w\x84\xe6\x8c\xa28T\x0c&\x81\x11\x02?\x8b\x18eB\x02\xc5\xce['

    c1_key = c1_pt[-32:]
    c2_key = c2_pt[-32:]
    c3_key = c3_pt[-32:]

    desired_pt = p32(attacker_id) + p64(0) + p64(2**64 - 1) + p32(1) + c1_key
    diff = xor(c1_pt, desired_pt)
    offset = 16 + 32 + 12 + 56
    fake_ct = c1_valid[:16] + hashlib.sha256(desired_pt).digest() + c1_valid[48:64] + xor(c1_valid[64:], diff)

    # c3_fake = c1_pt[]

    # c2_fake = bytes.fromhex('99b2e3c5679f62d7d17ccefa7be24f7b39b1b5b8c132197fa7a620c4ae1b9cd10501b27f2aa733d06251ff4d031f97d6cbaf378bc9ecc26baa33e5a23800000045a80260d84705b4e8aee520394e2a24ddabc983cd914312fc8060f6e885a9475479d2441399f73df544a020c364a8c30f6a5f185927dba3')
    # c3_fake = bytes.fromhex('e23e29378af08f4c7f3c35de03484d115f789b3d9af27d46466b6dfef261fd301ddeff858bd002d6779159149c02bf21b71a886a11448b5a936037e938000000973f29a953819a2bd86237b18b12e444b3503d0c69286b20b65ab1a49706d8b97fa7018b48684e7a6bf35575b9c2ded04d31fa8830972bc3')
    c1_fake = bytes.fromhex('301e05b27ac55861b0fc4ac1fab7d2636ad8162f80b7c897c4e98dff41f440f227d7174289888b0acfadf30f93aa835beec82b90254546078b366b803800000040058a1a7d2ee2468ce6fa75dcbf7ba6cb3c7174afb4ee5346891a3b2a182d484c42fbc855bd907d19d2820502288ab1ac8711922ac37c1e')

    frame = bytes.fromhex('028fa7b52ecb55dd52d86d255add9132bb150b45869a5c6f8c9a1e29bf3719677e615b29a4bdc7e791871fc7635f35c7727e37370f7e6f70315b54366c000000124500d62eae7f120857bcd8ebb38be38bcb4c8edf4233cc81cb8489f596ca2e5cbe6dab892f9dd6bc9d4deb1b3c64c3c01271e01f59af9ce8b273b5e93f35b52e746984a58cf31f0d22da1f0ed413824c5570b5acc80be2430708c5bb2dc04c614b6d53502bd29a96e13493')

    b = r.subscribe(fake_ct)
    print(r.list())
    print(r.decode(frame))
    # print(r.decode(playback_frames[0].data))



if __name__ == "__main__":
    main()
