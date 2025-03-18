import asyncio
import json
import time
from dataclasses import dataclass
from typing import Dict

@dataclass
class TargetInfo:
    host: str
    channel_ports: Dict[int, int]

    def port_for_channel(self, channel: int) -> int:
        return self.channel_ports[channel]

    @classmethod
    def load(cls, ports_file):
        with open(ports_file, 'r') as f:
            ip, *ports = f.read().split(' ')

        channel_ports = {channel: port for channel, port in enumerate(ports)}

        return cls(ip, channel_ports)

    async def capture(self, channel: int):
        ip = self.host
        port = self.port_for_channel(channel)

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

    async def capture_all_channels(self):
        output = []
        frames = await asyncio.gather(*[
            self.capture(channel) for channel in self.channel_ports.keys()
        ])

        for frame_group in frames:
            output.extend(frame_group)

        return output
