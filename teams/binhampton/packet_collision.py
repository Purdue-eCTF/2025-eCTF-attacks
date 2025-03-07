#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf
import json

context.arch = 'arm'

def conn():
    r = DecoderIntf('/dev/ttyACM0')

    return r

def construct_base_header(input):
    return [
        bytes.fromhex(input['encoded'])[:16],
        p32(input['channel']) + p64(input['timestamp']) + p32(64),
    ]

def main():
    r = conn()

    try:
        with open('base_headers.json', 'r') as f:
            data = json.loads(f.read())
            base_header1 = data['header1']
            base_header2 = data['header2']
    except:
        base_header1 = construct_base_header(json.loads('{"channel": 1, "timestamp": 2031166087333795, "encoded": "3f3940d60381eb4c54cfdb8b6120eae5f812acb499eb8a67e9e9c37dce86d0f17c37eb18e80af29571a6b27ca3e0c6501e5cbcf3d6f62ea00b437a8bb8c441a558ca4982bd843ffba823d72fe2529699"}'))
        base_header2 = construct_base_header(json.loads('{"channel": 2, "timestamp": 2031165969500088, "encoded": "02b82bffd8d4df740dc1349ffc94512690037fafaeb25238cbbb06cb205aa7c4d77af69e2c7ae0880025e7a78646b693a131b312185dd197e1a78b53d9fee4c5eebf60fadeaee839e6437aa7823444a7"}'))

    with open('c0_packets.json', 'r') as f:
        sniffed_packets = json.loads(f.read())

    for packet in sniffed_packets:
        header = packet[:16]

        payload = header + base_header1[-2] + base_header1[-1] + base_header2[-2] + base_header2[-1]
        output = r.decode(payload)

        base_hader1.append(output[0:16])
        base_hader1.append(output[16:32])
        base_hader2.append(output[32:48])
        base_hader2.append(output[48:64])

    with open('base_hedaers.json', 'w') as f:
        f.write(json.dumps({
            'header1': base_header1,
            'header2': base_header2,
        }))


if __name__ == "__main__":
    main()
