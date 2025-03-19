#!/usr/bin/env python3

import sys
import os
from pathlib import Path
import shutil
import argparse
import asyncio
import json
from .utils import TargetInfo, attack_folder, template_folder, load_playback_frames, save_frames, write_file

# parses decoder ids from the attack readme
def parse_readme(readme_file):
    def parse_id_from_section(section):
        for line in section.split('\n'):
            if 'decoder id' in line.lower():
                return int(line.split(':')[1].strip(), 0)

        return None

    parsed_ids = {}

    for part in readme_file.strip().split('## ')[1:]:
        name = part.split(' ')[0].strip().lower()
        id = parse_id_from_section(part)

        parsed_ids[f'{name}_id'] = id

    for expected_name in ['attacker_id', 'pirated_id', 'neighbor_id']:
        if expected_name not in parsed_ids:
            print(f'Warning: no decoder id found for {expected_name} decoder')
            parsed_ids[expected_name] = None

    return parsed_ids

def copy_and_format(src_file, dst_file, **kwargs):
    with open(src_file, 'r') as f:
        data = f.read()

    with open(dst_file, 'w') as f:
        f.write(data.format(**kwargs))

async def main():
    parser = argparse.ArgumentParser(
        prog = 'eCTF Initialize Attack folder',
        description = 'Initalizes files for attacking a team',
    )

    parser.add_argument('team_folder', help = 'Attack info folder released by eCTF organizers')

    args = parser.parse_args()

    team_folder = Path(args.team_folder).absolute()
    team_name = team_folder.name

    # parse decoder ids from readme
    with open(team_folder / 'README.md') as f:
        decoder_ids = parse_readme(f.read())

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
    copy_and_format(template_folder() / 'gen_pesky.py', team_attack_folder / 'gen_pesky.py', **decoder_ids)
    copy_and_format(template_folder() / 'exploit_template.py', team_attack_folder / 'solve.py', **decoder_ids)

    # copy subscriptions and packets
    shutil.copyfile(team_folder / 'README.md', team_attack_folder / 'README.md')
    shutil.copyfile(team_folder / 'own.sub', team_attack_folder / 'c1_valid.sub')
    shutil.copyfile(team_folder / 'expired.sub', team_attack_folder / 'c2_expired.sub')
    shutil.copyfile(team_folder / 'pirated.sub', team_attack_folder / 'c3_pirated.sub')
    shutil.copyfile(team_folder / 'ports.txt', team_attack_folder / 'ports.txt')

    # save captured frames from remote
    write_file(team_attack_folder / 'frames.json', json.dumps(frames))

    # save just first 16 playback frames to save space in git repo
    playback_frames = load_playback_frames(team_folder / 'recording.json')
    save_frames(team_attack_folder / 'playback_frames.json', playback_frames[:16])

if __name__ == '__main__':
    asyncio.run(main())
