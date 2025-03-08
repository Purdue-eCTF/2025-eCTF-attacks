import json
from dataclasses import dataclass

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

if __name__ == '__main__':
    main()
