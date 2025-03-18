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
    team_name = team_folder.name

    # capture frames
    target = TargetInfo.load(team_folder / 'ports.txt')
    print('starting frame capture...')
    frames = await target.capture_all_channels()
    print('frame capture done')

    # make attack folder
    team_attack_folder = (attack_folder() / 'teams' / team_name)
    team_attack_folder.mkdir(parents = True)

    # copy templates scripts
    shutil.copyfile(template_folder() / 'decoder.py', team_attack_folder / 'decoder.py')
    shutil.copyfile(template_folder() / 'exploit_template.py', team_attack_folder / 'solve.py')
    shutil.copyfile(template_folder() / 'gen_pesky.py', team_attack_folder / 'gen_pesky.py')

    # copy subscriptions and packets
    shutil.copyfile(team_folder / 'README.md', team_attack_folder / 'README.md')
    shutil.copyfile(team_folder / 'own.sub', team_attack_folder / 'c1_valid.sub')
    shutil.copyfile(team_folder / 'expired.sub', team_attack_folder / 'c2_expired.sub')
    shutil.copyfile(team_folder / 'pirated.sub', team_attack_folder / 'c2_pirated.sub')
    shutil.copyfile(team_folder / 'ports.txt', team_attack_folder / 'ports.txt')

    write_file(team_attack_folder / 'frames.json', json.dumps(frames))

if __name__ == '__main__':
    asyncio.run(main())
