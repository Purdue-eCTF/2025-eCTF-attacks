import json
from dataclasses import dataclass
from pwn import *

@dataclass
class CtPair:
    plaintext: bytes
    ciphertext: bytes

def pairs_for_chain(chain):
    out = []

    for i in range(len(chain) - 1):
        out.append(CtPair(
            ciphertext = chain[i],
            plaintext = chain[i + 1],
        ))

    return out

def main():
    with open('base_headers.json', 'r') as f:
        data = json.loads(f.read())
        base_header1 = list(map(lambda a: bytes.fromhex(a), data['header1']))
        base_header2 = list(map(lambda a: bytes.fromhex(a), data['header2']))

    assert len(base_header1) == len(set(base_header1))
    assert len(base_header2) == len(set(base_header2))
    pairs = pairs_for_chain(base_header1) + pairs_for_chain(base_header2)

    # best_score = 0xfffffffffffff
    # best_pair = None
    # for pair in pairs:
    #     num = u32(pair.plaintext[12:16])
    #     score = abs(0x20020000 - num)
    #     if score < best_score:
    #         best_score = score
    #         best_pair = pair

    for pair in pairs:
        if u32(pair.plaintext[12:16]) == 0x10010705:
            print(pair)
            return

    search_addr = 0x20020000
    # search_addr = 0x1000e714
    # search_addr = 0
    search_offset = 12
    # options = [(pair, hex(u32(pair.plaintext[search_offset:search_offset + 4])), abs(search_addr - u32(pair.plaintext[search_offset:search_offset + 4]))) for pair in pairs]
    options = [(pair, u32(pair.plaintext[search_offset:search_offset + 4])) for pair in pairs]
    # options.sort(key = lambda a: a[2])
    # print([o[1] for o in options[:10]])

    options.sort(key = lambda a: a[1])
    for option in options:
        addr = option[1]
        if addr >= 0x1000e000 and addr < 0x100193c0 and addr % 2 == 1:
            print(hex(addr))
            a = input('continue? ')

if __name__ == '__main__':
    main()
