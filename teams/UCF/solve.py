#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf, DecoderError
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

    attacker_id = 0x42f52b16
    pirated_id = 0x6f698f63
    pesky_id = 0x783d7dd0

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

    c4_frame = c4_frames[0]
    last2_block = c4_frame.data[-32:]
    # attempt to decrypt with padding oracle
    try_block = last2_block[:16]
    # padding_block = last2_block[16:]

    # returns true if padding correct
    def oracle(data):
        print(len(data))
        assert len(data) == 32
        sub = p32(4) + b'\0' * 16 + data
        try:
            r.subscribe(sub)
            sys.exit()
            return True
        except DecoderError as e:
            out = 'Cryptographic failure.' not in repr(e)

            return out

    BLOCK_SIZE = 16

    # some modified script from internet couldn't find my other padding oracle script
    def attack():
        guessed_clear = b''

        blocks = [b'\0' * 16, try_block]
        block_n = 1

        spliced_ciphertext = blocks[block_n - 1] + blocks[block_n]

        decoded_bytes = b'?' * BLOCK_SIZE #output of block cipher decoding values

        ##GET VALUE OF SECRET BYTE byte
        for byte in range( BLOCK_SIZE - 1, -1, -1 ):
            new_pad_len = BLOCK_SIZE - byte

            #Build hacked ciphertext tail with values to obtain desired padding
            hacked_ciphertext_tail = b''
            for padder_index in range( 1, new_pad_len ):
                hacked_ciphertext_tail += bytearray.fromhex('{:02x}'.format( new_pad_len ^ decoded_bytes[byte + padder_index] ) )

            found = False
            for i in range( 0, 256 ):
                # 1 byte to maniuplate padding bytes
                attack_str = bytearray.fromhex( '{:02x}'.format( ( i ^ spliced_ciphertext[byte] ) ) )
                # changed
                hacked_ciphertext = spliced_ciphertext[:byte] + attack_str + hacked_ciphertext_tail + try_block

                print(byte)
                print(guessed_clear)
                if( oracle( hacked_ciphertext ) ):

                    if byte == 0:
                        test_correctness = bytearray.fromhex( '{:02x}'.format( ( 1 ^  hacked_ciphertext[byte] ) ) )  + hacked_ciphertext[byte+1:]
                    else:
                        test_correctness = hacked_ciphertext[:byte - 1] + bytearray.fromhex( '{:02x}'.format( ( 1 ^  hacked_ciphertext[byte] ) ) )  + hacked_ciphertext[byte:]
                        # changed removed not
                        if( not oracle( test_correctness ) ):
                            continue

                    found = True
                    decoded_bytes = decoded_bytes[:byte] + bytearray.fromhex('{:02x}'.format( hacked_ciphertext[byte] ^ new_pad_len ) ) + decoded_bytes[byte + 1:]
                    guessed_clear = bytearray.fromhex('{:02x}'.format( i ^ new_pad_len ) ) + guessed_clear
                    break

            if not found:
                a = None
                a.b = 2

        # return guessed_clear[:-guessed_clear[-1]] #remove padding!
        return guessed_clear

    real_block = bytes(attack())
    print(real_block)
    desired_n = p32(attacker_id) + b'\0' * 12

    fake_sub = p32(4) + xor(real_block, desired_n) + last2_block
    print(r.subscribe(fake_sub))

    # # c2_valid = p32(2) + c1_valid[4:]
    # # c3_valid = p32(3) + c1_valid[4:]
    # # c4_valid = p32(4) + c1_valid[4:]
    # c3_iv = c3_pirated[4:20]
    # new_iv = xor(xor(p32(attacker_id), p32(pirated_id)), c3_iv[:4]) + c3_iv[4:]
    # c3_valid = p32(3) + new_iv + c3_pirated[20:]

    # # r.subscribe(c2_valid)
    # r.subscribe(c3_valid)
    # # r.subscribe(c4_valid)

    # # print(r.decode(c2_frames[0].data))
    # print(r.decode(c3_frames[0].data))
    print(r.decode(c4_frames[0].data))

    # print(r.list())
    # b = r.subscribe(b'example')
    # a = r.decode(b'example')



if __name__ == "__main__":
    main()
