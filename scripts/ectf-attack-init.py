#!/usr/bin/env python3

import sys
import os
from pathlib import Path
import shutil

def main():
    attack_folder = Path(os.path.realpath(__file__)).parent.parent.absolute()
    template_folder = attack_folder / 'exploit_templates'
    team_folder = Path(os.getcwd()).absolute()
    team_name = team_folder.name

    team_attack_folder = (attack_folder / 'teams' / team_name)
    team_attack_folder.mkdir(parents = True)

    # copy templates scripts
    shutil.copyfile(template_folder / 'decoder.py', team_attack_folder / 'decoder.py')
    shutil.copyfile(template_folder / 'exploit_template.py', team_attack_folder / 'solve.py')

    # copy subscriptions and packets
    shutil.copyfile(team_folder / 'README.md', team_attack_folder / 'README.md')
    shutil.copyfile(team_folder / 'own.sub', team_attack_folder / 'c1_valid.sub')
    shutil.copyfile(team_folder / 'expired.sub', team_attack_folder / 'c2_expired.sub')
    shutil.copyfile(team_folder / 'pirated.sub', team_attack_folder / 'c2_pirated.sub')
    

if __name__ == '__main__':
    main()
