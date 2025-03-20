#!/usr/bin/env python3

from ectf25.utils.decoder import DecoderIntf


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

    recorded = bytes.fromhex(
        "01000000186a3f83f661cb91a2f97d41a291abe1056b710555abb28d3075f55446232a8f0829a8647dfa46c7abc1ac546a408fb5e7423d8bcea8ef5f59d9576d90e05ea7029bbffcb2b5229d191c91d8330a3a43f01d5ef5f7f82fc4154c50e98c54bc95")

    valid = [
        {"channel": 1, "timestamp": 1959707469104610, "encoded": "0100000090ed1d905f7d5bbc8577d21dc78b4a4e89df03cdd606b545f716eddc5820d19b30acad67988b7f3e3b8f19ed395abb809eda5409b5fa75fb58b781b227f1055e0709e7fdbe60f39f15e9da16893da03f2642233dedd7bd41950cc04537e84d82"},
        {"channel": 1, "timestamp": 1959707469606098, "encoded": "010000007afd72d26e0bb47e004b2f2d86a9932238ac069399eb4fdfaa200cbb1268a68083c07d9c9725c7b853a24d7ff835cafffdbc87a01edce85d6a55f24dfa2e9b213cd8bae13e7190db8454a7802988d2b44f5412cee85b0f2c043f2f94dccbfbd4"},
        {"channel": 1, "timestamp": 1959707470107441, "encoded": "0100000087c54b361ea4e5713559455a3bb61d02b4d00c2b28b704d85780b1138f0159d9df5058157e3b32aa2adbee4dc6c0eb39f2d274dcd1b4d39dd14b866a2f8425221cc696ef182087e631d1ecb6aef2b74b83d0cdfbd155fe9d50a4586aab7f4a99"},
        {"channel": 1, "timestamp": 1959707470608905, "encoded": "01000000d856094e073fd0baceb12851aa835d95c367196a4e4d64a78e23a5d18f78ec72870cba829a92d1e9a2a0c314a1664536ee2ae98b176cb328175d9a0f0b174a605a92add67592902f5fbe6f4021e6bcf1dbb575dd5d980e13fbcc4404ea1f61a8"},
        {"channel": 1, "timestamp": 1959707471110275, "encoded": "010000002598d43686fe69b2f1a74618d7cd700a2a8f19b14424ceab3779ba0aaec5d384480d360298b57d104722ae1f6a285484b92b583e5e2de63a00d8176a51e8e4d59d5c1fa2613f1ba75a9ea91f8955b260bdd89846c47a4e2d3b96c13452c7cd77"},
        {"channel": 1, "timestamp": 1959707471611676, "encoded": "0100000000e1d9d187c4f96782f1b7de454cea948c5e2ca3e11102c155a4a012b420659cb920217753e44e0ba7b6d1e62f97f14b4d9841ce0114c5d167f1f83bc3f9650912f5ddb92dfbb1f09e4f2ffa759cdf74c773bf7d0be92489f35f9f2d92808009"},
        {"channel": 1, "timestamp": 1959707472113113, "encoded": "010000002b3aee8ec825a94e8158e874d3825663aa37b552d1ec3e736e899d57fd81a3e4d6e471ea91b002099f1480e415917fe0b862912e0b4d6a305c55982a5d2f5dd813de892abefa9d5ff14e8797bf8e94470ca72c7e1c41a316787712d1a5f99423"},
    ]

    encrypt = recorded[4:]
    idx = 0
    for i in range(0, len(encrypt)-16, 16):
        frame = bytes.fromhex(valid[idx]["encoded"])
        print(r.decode(frame[:36]+encrypt[i:i+32]+frame[36+32:]))
        idx += 1


if __name__ == "__main__":
    main()
