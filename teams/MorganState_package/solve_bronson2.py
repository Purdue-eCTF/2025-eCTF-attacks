#!/usr/bin/env python3

import sys
from decoder import DecoderIntf, DecoderError
import hashlib
import struct


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

    own_sub = bytes.fromhex('301e05b27ac55861b0fc4ac1fab7d2636ad8162f80b7c897c4e98dff41f440f227d7174289888b0acfadf30f93aa835beec82b90254546078b366b803800000040058a1a7d2ee2468ce6fa75dcbf7ba6cb3c7174afb4ee5346891a3b2a182d484c42fbc855bd907d19d2820502288ab1ac8711922ac37c1e')
    # own_sub = bytes.fromhex('301e05b27ac55861b0fc4ac1fab7d263797ae70e395bd6aa293712ff2d7e034e846c6ded54d43bf109fa02fcdea061c0eec82b90254546078b366b803800000040058a1a2e86e5ee33b7fc75d29fc4df7b4577f4afb4ee5346891a3b2a182d484c42fbc855bd907d19d2820502288ab1ac8711922ac37c1e')

    recorded = {"timestamp": 123919916287989, "encoded": "028fa7b52ecb55dd52d86d255add9132bb150b45869a5c6f8c9a1e29bf3719677e615b29a4bdc7e791871fc7635f35c7727e37370f7e6f70315b54366c000000124500d62eae7f120857bcd8ebb38be38bcb4c8edf4233cc81cb8489f596ca2e5cbe6dab892f9dd6bc9d4deb1b3c64c3c01271e01f59af9ce8b273b5e93f35b52e746984a58cf31f0d22da1f0ed413824c5570b5acc80be2430708c5bb2dc04c614b6d53502bd29a96e13493"}

    r.subscribe(own_sub)
    print(r.decode(bytes.fromhex(recorded["encoded"])))


if __name__ == "__main__":
    main()
