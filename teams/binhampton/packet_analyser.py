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

    search_addr = 0x20020000
    # search_addr = 0x1000e714
    options = [(pair, hex(u32(pair.plaintext[12:16])), abs(search_addr - u32(pair.plaintext[12:16]))) for pair in pairs]
    options.sort(key = lambda a: a[2])
    print([o[1] for o in options[:10]])

if __name__ == '__main__':
    main()
