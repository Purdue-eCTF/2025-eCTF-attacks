import json

def main():
    with open('c0_packets.json', 'r') as f:
        packets = json.loads(f.read())

    with open('nohup.out', 'r') as f:
        nohup = f.read()

    for line in nohup.split('\n'):
        line = line.replace('\'', '"')
        packet = json.loads(line)
        packets.append(packet)

    packets.sort(key = lambda a: a['timestamp'])
    print(len(packets))
    with open('c0_packets_merged.json', 'w') as f:
        f.write(json.dumps(packets))

if __name__ == '__main__':
    main()
