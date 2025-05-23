#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf

context.arch = 'thumb'

def conn():
    r = DecoderIntf('/dev/ttyACM0')

    return r


def main():
    r = conn()

    print(r.list())
    b = r.subscribe(b'example')
    a = r.decode(b'example')



if __name__ == "__main__":
    main()
