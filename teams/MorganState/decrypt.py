import hashlib

pt = b'\xc5\xd9p\xf8\xa6\xc8-"F\xe3\x05\x00\xac\x80\xaa\xee\t*\x06\x00\x02\x00\x00\x00P_\xdf\x0b\xc0!\xdbF\xa6\'\x8e\xdb0\xa3\xda2\xcd-\ne\xd3\xfa\xd4\x9ei\x1e\xa7Eh\xb4*'
print(len(pt))

channel_2_key = b'P_\xdf\x0b\xc0!\xdbF\xa6\'\x8e\xdb0\xa3\xda2\xcd-\ne\xd3\xfa\xd4\x9ei\x1e\xa7Eh\xb4*'

expired_sub = bytes.fromhex(
    '99b2e3c5679f62d7d17ccefa7be24f7baf6bc365d4069e039f7b98673ad1a1e51cda83605c12335681d9db3734fca31fcbaf378bc9ecc26baa33e5a23800000045a802607e8f2896ae4de02095ce80cad481cf03cd914312fc8060f6e885a9475479d2441399f73df544a020c364a8c30f6a5f185927dba3')
pirated_sub = bytes.fromhex(
    'e23e29378af08f4c7f3c35de03484d1130ee09db3893b8c3e617f5f8c074d7c4a84a1a6daec634dad54448acd748f7b1b71a886a11448b5a936037e938000000acd9b167b4dde623f03031b178621515c8d03b8c69286b20b65ab1a49706d8b97fa7018b48684e7a6bf35575b9c2ded04d31fa8830972bc3')
own_sub = bytes.fromhex('301e05b27ac55861b0fc4ac1fab7d263797ae70e395bd6aa293712ff2d7e034e846c6ded54d43bf109fa02fcdea061c0eec82b90254546078b366b803800000040058a1a2e86e5ee33b7fc75d29fc4df7b4577f4afb4ee5346891a3b2a182d484c42fbc855bd907d19d2820502288ab1ac8711922ac37c1e')

tag = expired_sub[:16]
sha = expired_sub[16:48]
nonce = expired_sub[48:60]
l = expired_sub[60:64]


for i in range(256):
    if hashlib.sha256(pt+bytes([i])).digest() == sha:
        print(i)
        print((pt + bytes([i])))
        print((pt + bytes([i])).hex())

pt = b'\xfe?\xe86\xe7\\|\x08(R\x06\x00\xf3p\xf1Q{\x80\x06\x00\x03\x00\x00\x00\x8a\xcd\x16\xd4\x1d\xd2)\xe9T^[w\x84\xe6\x8c\xa28T\x0c&\x81\x11\x02?\x8b\x18eB\x02\xc5\xce'
tag = pirated_sub[:16]
sha = pirated_sub[16:48]
nonce = pirated_sub[48:60]
l = pirated_sub[60:64]

for i in range(256):
    if hashlib.sha256(pt+bytes([i])).digest() == sha:
        print(i)
        print((pt + bytes([i])))
        print((pt + bytes([i])).hex())

pt = b'\xc5\xd9p\xf8S\xa8\x07\xa8\xbfQ\x06\x00\x0e \xbfy\xb0y\x06\x00\x01\x00\x00\x00\xa8\xe9\xa3\tv9\xcf\xd9.OK\xee\x94tX\x88Q\x9b_V\x83\xfb\xe4\xeb8\xc7,\xeei%\x18'

tag = own_sub[:16]
sha = own_sub[16:48]
nonce = own_sub[48:60]
l = own_sub[60:64]

for i in range(256):
    if hashlib.sha256(pt+bytes([i])).digest() == sha:
        print(i)
        print((pt + bytes([i])))
        print((pt + bytes([i])).hex())
