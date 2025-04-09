#!/usr/bin/python3.8
from pwn import xor
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long

# round_keys = b'L\xf7a\xd4\x85I\x9b\xd2\nH\x0b\xab\xf8*<\xd8G9V\xae\x9e`{\x0eb\xf1\x88)&\x8f\xf8\x80B@\xb5\xb4\x12\rO\xcbo\xed\xee\x1b\x98\x89J\x82\x13\xe6\x1b\xd3(\xaa1\xb5\x02\x91\xc1Q]\x1d!\x90\t\xfe\x14\xddA\xf0\xf5auW%\xfc\x00\xd0\x8c\xcb\x8c\xb5\xa5e'
# last 4 round keys
# round_keys = bytes.fromhex('02edc8784fec1813432423c7e168e40042d94cac7ba7ed06adddd10ff5fc6c50c54c40e04d2425bb13437209384e9a02cdcc1970397ea1aad67a3c095821bd5f')
# round keys 13, 12, 11, 10 (counting from 0 as first round)
round_keys = bytes.fromhex('42d94cac7ba7ed06adddd10ff5fc6c50c54c40e04d2425bb13437209384e9a02cdcc1970397ea1aad67a3c095821bd5f33735d3f8868655b5e6757b22b0de80b')
# round_keys = bytes.fromhex('6e6f666c61676f6e746869736368616e5e20666c6167205e303030353962373237343437333961335e2074696d65205e39336637333864323639333933663364912c8502edc8784fec1813432423c7e168e40042d94cac7ba7ed06adddd10ff5fc6c50c54c40e04d2425bb13437209384e9a02cdcc1970397ea1aad67a3c095821bd5f33735d3f8868655b5e6757b22b0de80ba09dcceff4b2b8daef049da38e5b815691b11bd7bb1b3864d60f32e9756abfb9dc5625ec542f74351bb62579615f1cf55e50d61e2aaa23b36d140a8da3658d50e7ee51a0887951d94f99514c7ae9398c33c4b59b74faf5ad47be293ece7187dd77794c826f970079c7e00095')
round_keys = b'\x02\xed\xc8xO\xec\x18\x13C$#\xc7\xe1h\xe4\x00B\xd9L\xac{\xa7\xed\x06\xad\xdd\xd1\x0f\xf5\xfclP\xc5L@\xe0M$%\xbb\x13Cr\t8N\x9a\x02\xcd\xcc\x19p9~\xa1\xaa\xd6z<\tX!\xbd_3s]?\x88he[^gW\xb2+\r\xe8\x0b\xa0\x9d\xcc\xef\xf4\xb2\xb8\xda\xef\x04\x9d\xa3\x8e[\x81V\x91\xb1\x1b\xd7\xbb\x1b8d\xd6\x0f2\xe9uj\xbf\xb9\xdcV%\xecT/t5\x1b\xb6%ya_\x1c\xf5^P\xd6\x1e*\xaa#\xb3m\x14\n\x8d\xa3e\x8dP\xe7\xeeQ\xa0\x88yQ\xd9O\x99QLz\xe99\x8c3\xc4\xb5\x9bt\xfa\xf5\xadG\xbe)>\xceq\x87\xddwyL\x82o\x97\x00y\xc7\xe0\x00\x95'


Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

Rcon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]


def shift(s):
    return bytes([s[1], s[2], s[3], s[0]])


def sub(s):
    return bytes([Sbox[s[0]], Sbox[s[1]], Sbox[s[2]], Sbox[s[3]]])


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

def process_key(key):
    key = bytes2matrix(key)
    inv_mix_columns(key)
    unmix_key = matrix2bytes(key)
    return list(chunks(unmix_key, 4))

# key should be list of length 8 of 4 bytes each element
def invert_double_round(key, first_n):
    prev_key = [b''] * 8

    prev_key[7] = xor(key[6], key[7])
    prev_key[6] = xor(key[5], key[6])
    prev_key[5] = xor(key[4], key[5])
    prev_key[4] = xor(sub(key[3]), key[4])
    prev_key[3] = xor(key[2], key[3])
    prev_key[2] = xor(key[1], key[2])
    prev_key[1] = xor(key[0], key[1])
    prev_key[0] = xor(xor(key[0], sub(shift(prev_key[7]))), bytes([Rcon[first_n // 2], 0, 0, 0]))

    return prev_key

def forward_double_round(key, first_n):
    next_key = [b''] * 8

    next_key[0] = xor(xor(key[0], sub(shift(key[7]))), bytes([Rcon[first_n // 2], 0, 0, 0]))
    next_key[1] = xor(next_key[0], key[1])
    next_key[2] = xor(next_key[1], key[2])
    next_key[3] = xor(next_key[2], key[3])
    next_key[4] = xor(sub(next_key[3]), key[4])
    next_key[5] = xor(next_key[4], key[5])
    next_key[6] = xor(next_key[5], key[6])
    next_key[7] = xor(next_key[6], key[7])

    return next_key

def invert_schedule(key, round):
    """
    K(i-1, 4) = K(i, 3) XOR K(i, 4)
    K(i-1, 3) = K(i, 2) XOR K(i, 3)
    K(i-1, 2) = K(i, 1) XOR K(i, 2)
    K(i-1, 1) = K(i, 1) XOR sub(shift(K(i-1, 4)) XOR RCON(i)
    """

    prev_key = [b""] * 4

    prev_key[3] = xor(key[2], key[3])
    prev_key[2] = xor(key[1], key[2])
    prev_key[1] = xor(key[0], key[1])
    prev_key[0] = xor(xor(key[0], sub(shift(prev_key[3]))),
                      bytes([Rcon[round], 0, 0, 0]))

    return prev_key

offset = 16

rk13 = process_key(round_keys[offset:offset+16])
rk12 = process_key(round_keys[offset+16:offset+32])
rk11 = process_key(round_keys[offset+32:offset+48])
rk10 = process_key(round_keys[offset+48:offset+64])

# current_key = list(chunks(round_keys[offset:offset+32], 4))
current_key = rk12 + rk13

# key_round10 = list(chunks(round_keys[offset+32:offset+64], 4))
# key_round10 = key_round10[4:8] + key_round10[0:4]
prev_key = rk10 + rk11

print('prev')
print(prev_key)
print(invert_double_round(current_key, 12))

print(xor(prev_key[4], current_key[4]))
print(sub(current_key[3]))

print('next')
print(current_key)
print(forward_double_round(prev_key, 10))

# for i in range(len(round_keys) - 64):
#     current_key = list(chunks(round_keys[i:i+32], 4))
#     # current_key = key_part[4:8] + key_part[0:4]

#     key_round10 = list(chunks(round_keys[i+32:i+64], 4))
#     # key_round10 = key_round10[4:8] + key_round10[0:4]

#     for j in range(15):
#         invert_key = invert_double_round(current_key, j)
#         if invert_key == key_round10:
#             print(i)

#         invert_key = invert_double_round(key_round10, j)
#         if invert_key == current_key:
#             print(i)

#     # print('prev')
#     # print(key_round10)
#     # print(invert_double_round(current_key, 12))

#     # print('next')
#     # print(current_key)
#     # print(forward_double_round(key_round10, 10))


# current_round = 12
# while current_round > 0:
#     current_key = invert_double_round(current_key, current_round)
#     current_round -= 2

# print(b''.join(current_key[:8]))

# for idx in range(16, len(round_keys)-16):
#     prev_key = list(chunks(round_keys[idx-16:idx], 4))
#     cur_key = list(chunks(round_keys[idx:idx+16], 4))
#     print(cur_key)

#     for j in range(10):
#         cur_key = invert_schedule(cur_key, j)
#         if cur_key != prev_key:
#             continue
#         print("Found!")

#         for i in range(j-1, 0, -1):
#             cur_key = invert_schedule(cur_key, i)
#         break


# key = b"".join(cur_key).hex()
# print("[+] Master key:", key)
