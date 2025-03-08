#!/bin/sh

while [ true ]
do
  # ports 3-3 for my laptop
  echo 'Cycling board power...'
  uhubctl -a cycle
  sleep 10
  echo 'Running decryption oracles...'
  python packet_collision.py
  echo 'Done'
done
