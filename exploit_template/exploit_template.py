#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf

context.arch = 'thumb'

def conn():
    r = DecoderIntf('/dev/ttyACM0')

    return r

def read_if_exists(name):
    try:
        with open('c1_valid.sub', 'rb') as f:
            return f.read()
    except:
        return None

def main():
    r = conn()

    c1_valid = read_if_exists('c1_valid.sub')
    c2_expired = read_if_exists('c2_expired.sub')
    c3_pirated = read_if_exists('c3_pirated.sub')

    print(r.list())
    b = r.subscribe(b'example')
    a = r.decode(b'example')



if __name__ == "__main__":
    main()
