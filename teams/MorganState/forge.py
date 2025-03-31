from pwn import xor
import hashlib
import struct
original_sub = bytes.fromhex(
    "c5d970f8a6c82d2246e30500ac80aaee092a060002000000505fdf0bc021db46a6278edb30a3da32cd2d0a65d3fad49e691ea74568b42a43")

key = original_sub[-32:]
new_sub = struct.pack("<IQQI32s", 0xf870d9c5, 0, 1 << 63, 2, key)
print(original_sub.hex())
print(new_sub.hex())

expired_sub = bytes.fromhex(
    '99b2e3c5679f62d7d17ccefa7be24f7baf6bc365d4069e039f7b98673ad1a1e51cda83605c12335681d9db3734fca31fcbaf378bc9ecc26baa33e5a23800000045a802607e8f2896ae4de02095ce80cad481cf03cd914312fc8060f6e885a9475479d2441399f73df544a020c364a8c30f6a5f185927dba3')

original_encrypted = expired_sub[64:]


new_encrypted = xor(original_encrypted, original_sub, new_sub)

new_hash = hashlib.sha256(new_sub).digest()

new_subscription = expired_sub[:16] + \
    new_hash + expired_sub[48:64] + new_encrypted


print(new_subscription)
print(new_subscription.hex())

# 91
# b'\xfe?\xe86\xe7\\|\x08(R\x06\x00\xf3p\xf1Q{\x80\x06\x00\x03\x00\x00\x00\x8a\xcd\x16\xd4\x1d\xd2)\xe9T^[w\x84\xe6\x8c\xa28T\x0c&\x81\x11\x02?\x8b\x18eB\x02\xc5\xce['
# fe3fe836e75c7c0828520600f370f1517b800600030000008acd16d41dd229e9545e5b7784e68ca238540c268111023f8b18654202c5ce5b

original_sub = bytes.fromhex(
    "fe3fe836e75c7c0828520600f370f1517b800600030000008acd16d41dd229e9545e5b7784e68ca238540c268111023f8b18654202c5ce5b")

key = original_sub[-32:]
new_sub = struct.pack("<IQQI32s", 0xf870d9c5, 0, 1 << 63-1, 3, key)
print(original_sub.hex())
print(new_sub.hex())

pirated_sub = bytes.fromhex(
    'e23e29378af08f4c7f3c35de03484d1130ee09db3893b8c3e617f5f8c074d7c4a84a1a6daec634dad54448acd748f7b1b71a886a11448b5a936037e938000000acd9b167b4dde623f03031b178621515c8d03b8c69286b20b65ab1a49706d8b97fa7018b48684e7a6bf35575b9c2ded04d31fa8830972bc3')

original_encrypted = pirated_sub[64:]


new_encrypted = xor(original_encrypted, original_sub, new_sub)

new_hash = hashlib.sha256(new_sub).digest()

new_subscription = pirated_sub[:16] + \
    new_hash + pirated_sub[48:64] + new_encrypted


print(new_subscription)
print(new_subscription.hex())

# 48
# b'\xc5\xd9p\xf8S\xa8\x07\xa8\xbfQ\x06\x00\x0e \xbfy\xb0y\x06\x00\x01\x00\x00\x00\xa8\xe9\xa3\tv9\xcf\xd9.OK\xee\x94tX\x88Q\x9b_V\x83\xfb\xe4\xeb8\xc7,\xeei%\x180'
# c5d970f853a807a8bf5106000e20bf79b079060001000000a8e9a3097639cfd92e4f4bee94745888519b5f5683fbe4eb38c72cee69251830
original_sub = bytes.fromhex(
    "c5d970f853a807a8bf5106000e20bf79b079060001000000a8e9a3097639cfd92e4f4bee94745888519b5f5683fbe4eb38c72cee69251830")

key = original_sub[-32:]
new_sub = struct.pack("<IQQI32s", 0xf870d9c5, 0, 1 << 63-1, 1, key)
print(original_sub.hex())
print(new_sub.hex())

own_sub = bytes.fromhex('301e05b27ac55861b0fc4ac1fab7d263797ae70e395bd6aa293712ff2d7e034e846c6ded54d43bf109fa02fcdea061c0eec82b90254546078b366b803800000040058a1a2e86e5ee33b7fc75d29fc4df7b4577f4afb4ee5346891a3b2a182d484c42fbc855bd907d19d2820502288ab1ac8711922ac37c1e')

original_encrypted = own_sub[64:]


new_encrypted = xor(original_encrypted, original_sub, new_sub)

new_hash = hashlib.sha256(new_sub).digest()

new_subscription = own_sub[:16] + \
    new_hash + own_sub[48:64] + new_encrypted


print(new_subscription)
print(new_subscription.hex())
