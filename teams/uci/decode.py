from Crypto.Cipher import AES
from pwn import *
from Crypto.Hash import SHA256
payload = b'\x01\x00\x00\x00\xf6\xc3{\x84\xc4eZ\xa2\xee=\x9d\xfa\xa7\n\xf46\xce\xe2#"H\x91\xe6E\xc4\x18\x98\x99`\x01E}B\xb2;Zf\x92)@M\x83\x9d\xd4\xa0/\x17/i\xae\x7f{`|\x96a2\x06\xaf\xea\xa90:\x98\xe0\xdf1\xca\xe8\x0c\x9f\x13\xa0\xdd\xe8&\xfc\xc2#Y\x05\x91\xc4\x9d'
channel = u32(payload[:4])
mask_key = payload[4:20]
msg_key = payload[20:36]
data_key = payload[36:52]
sub_key = payload[52:68]
check_sum = payload[68:88]
print(f"{channel=}")
print(f"{mask_key.hex()=}")
print(f"{msg_key.hex()=}")
print(f"{data_key.hex()=}")
print(f"{sub_key.hex()=}")
print(f"{check_sum.hex()=}")

frame = {"timestamp": 124768822069727, "encoded": "01000000df8951017a710000400000002495036e612c01835188f04e44d36d67be88ed43b0a75d684d9a0260f33fa4a2818beefe75090ff040d89bdd9a46dd6a3a63762b055369f91134246f5106ce62028eea2d0c9b2fe89ff3b42ba3e70cdf4630e67609617f0b50830ec54dd5a0ea4b1c29fd8c84ac5be8be32c339686fa6"}
ct = frame["encoded"]
timestamp = frame["timestamp"]

frame_channel = ct[:8]
frame_time = ct[8:24]
frame_size = ct[24:32]

frame_iv = ct[32:64]

print(frame_channel, frame_time, frame_size, frame_iv)


def compute_hash(data):
    """Compute the SHA-256 hash of the data"""
    hash = SHA256.new()
    hash.update(data)
    return hash.digest()


def pad(data, block_size):
    """Pad the data to the block size"""
    assert type(data) == bytes, "Data must be bytes"
    extra = len(data) % block_size
    if extra == 0:
        padding_length = 0
    else:
        padding_length = block_size - extra
    return data + b'\x00' * padding_length


def sym_decrypt(key, iv, data):
    cipher = AES.new(key=key, iv=iv, mode=AES.MODE_CBC)
    return cipher.decrypt(data)


def xor(byte1, byte2):
    """XOR two bytes"""
    # Extend them two same length
    if len(byte1) < len(byte2):
        byte = byte1
        byte1 = byte2
        byte2 = byte
    byte2 = byte2.ljust(len(byte1), b'\x00')
    return bytes(a ^ b for a, b in zip(byte1, byte2))


c1_key = xor(
    compute_hash(xor(mask_key, timestamp.to_bytes(8, 'little'))), msg_key)
c1_key = c1_key[:16]
c1_ct = bytes.fromhex(ct[64:128])
c1 = sym_decrypt(c1_key, bytes.fromhex(frame_iv), c1_ct)
print(c1)
print(u64(c1[8:16]), timestamp)
nonce = c1[:8] + c1[16:24]

# Prepare C2 info
c2_key = xor(nonce, data_key)
c2_ct = bytes.fromhex(ct[128:])
c2 = sym_decrypt(c2_key, bytes.fromhex(frame_iv), c2_ct)
print(c2)
