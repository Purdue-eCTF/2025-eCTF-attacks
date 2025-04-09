#!/bin/sh

cd $(dirname $0)

python -m venv .venv --prompt ectf-attack
. ./.venv/bin/activate

# misc dependancies
python -m pip install pwntools loguru pycryptodome

# host tools from organizers
python -m pip install ectf_host_tools/

# attack scripts and utilities
python -m pip install -e ectf25_attack/
