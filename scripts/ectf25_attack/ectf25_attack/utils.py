import asyncio
import json
import time
from dataclasses import dataclass
from typing import Dict, List
from pathlib import Path
import os

def attack_folder():
    return Path(os.path.realpath(__file__)).parent.parent.parent.parent.absolute()

def template_folder():
    return attack_folder() / 'exploit_template'

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

@dataclass
class Frame:
    channel: int
    timestamp: int
    data: bytes

    @classmethod
    def from_json(cls, data):
        return Frame(data['channel'], data['timestamp'], bytes.fromhex(data['encoded']))

    @classmethod
    def from_playback_json(cls, data):
        return Frame(1, data['timestamp'], bytes.fromhex(data['encoded']))

    def to_json(self):
        return {
            'channel': self.channel,
            'timestamp': self.timestamp,
            'encoded': self.data.hex(),
        }

    def with_data(self, data: bytes):
        return Frame(channel = self.channel, timestamp = self.timestamp, data = data)

def load_frames(file) -> List[Frame]:
    with open(file, 'r') as f:
        data = json.loads(f.read())

    return [Frame.from_json(entry) for entry in data]

def load_playback_frames(file) -> List[Frame]:
    with open(file, 'r') as f:
        data = json.loads(f.read())

    return [Frame.from_playback_json(entry) for entry in data]

def save_frames(file, data: List[Frame]):
    data_ser = [frame.to_json() for frame in data]

    with open(file, 'w') as f:
        f.write(json.dumps(data_ser))

def filter_channel(frames: List[Frame], channel: int) -> List[Frame]:
    return [frame for frame in frames if frame.channel == channel]

# Attack for teams which allow multiple frames of the same timestamp
def repeated_frame(frames: List[Frame]) -> List[Frame]:
    return [frames[0], frames[0]]

# Attack for teams with a per channel timestamp check
def per_channel_check(frames: List[Frame]) -> List[Frame]:
    start_frame = filter_channel(frames, 0)[0]
    end_frame = filter_channel(frames, 1)[-1]

    assert end_frame.timestamp >= start_frame.timestamp

    return [end_frame, start_frame]

def write_file(name, data):
    format = 'wb' if type(data) == bytes else 'w'
    with open(name, format) as f:
        f.write(data)
