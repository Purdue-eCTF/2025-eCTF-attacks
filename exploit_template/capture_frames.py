import asyncio
import json
import time


async def capture(ip, port, channel):
    reader, writer = await asyncio.open_connection(ip, port)
    buffer = b""
    frames = []
    start = time.time()
    while time.time() - start < 10 or len(frames) < 2:
        buffer += await reader.read(1024)
        *lines, rest = buffer.split(b"\n")
        frames.extend(
            frame for frame in map(json.loads, lines) if frame["channel"] == channel
        )  # why are channel 0 frames being sent on other ports??
        buffer = rest
    return frames


async def main():
    with open("ports.txt") as f:
        ip, *ports = f.read().split(" ")

    frames = await asyncio.gather(*[
        capture(ip, port, channel) for channel, port in enumerate(ports)
    ])

    with open("frames.json", "w") as f:
        json.dump(frames, f)


if __name__ == "__main__":
    asyncio.run(main())
