#!/usr/bin/env python3

import sys
import os
from pathlib import Path
import shutil
import argparse
import asyncio
import json
from .utils import TargetInfo, attack_folder, template_folder

def write_file(name, data):
    format = 'wb' if type(data) == bytes else 'w'
    with open(name, format) as f:
        f.write(data)

async def main():
    parser = argparse.ArgumentParser(
        prog = 'eCTF Initialize Attack folder',
        description = 'Initalizes files for attacking a team',
    )

    parser.add_argument('team_folder', help = 'Attack info folder released by eCTF organizers')

    args = parser.parse_args()

    team_folder = Path(args.team_folder).absolute()
    frames_file = team_folder / 'frames.json'

    # load old frames if they exists
    try:
        with open(frames, 'r') as f:
            frames = json.loads(f.read())
    except:
        frames = []

    # capture frames
    target = TargetInfo.load(team_folder / 'ports.txt')

    print('starting frame capture...')
    frames.extend(await target.capture_all_channels())
    print('frame capture done')

    write_file(frames_file, json.dumps(frames))

if __name__ == '__main__':
    asyncio.run(main())
