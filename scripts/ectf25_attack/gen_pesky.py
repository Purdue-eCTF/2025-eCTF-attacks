#!/usr/bin/env python3

import sys
import os
from pathlib import Path
import shutil
import argparse
import asyncio
import json
from .utils import TargetInfo, attack_folder, template_folder
from zipfile import ZipFile

def write_file(name, data):
    format = 'wb' if type(data) == bytes else 'w'
    with open(name, format) as f:
        f.write(data)

async def main():
    parser = argparse.ArgumentParser(
        prog = 'eCTF Initialize Attack folder',
        description = 'Initalizes files for attacking a team',
    )

    parser.add_argument('attack_folder', help = 'Attack folder containing the pesky frames')

    args = parser.parse_args()

    attack_folder = Path(args.attack_folder).absolute()
    team_name = attack_folder.name
    pesky_frames = attack_folder / 'pesky_frames.json'
    pesky_script = template_folder() / 'pesky_neighbor.py'

    with ZipFile(attack_folder / f'pesky_neighbor_{team_name}.zip', 'w') as output:
        output.write(pesky_frames, arcname = 'pesky_frames.json')
        output.write(pesky_script, arcname = 'pesky_neighbor.py')

if __name__ == '__main__':
    asyncio.run(main())
