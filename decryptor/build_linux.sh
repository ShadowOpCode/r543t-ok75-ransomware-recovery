#!/usr/bin/env sh
set -eu

cc -std=c11 -O3 -Wall -Wextra -Wpedantic -pthread -static \
  -D_FILE_OFFSET_BITS=64 \
  r543t_recover.c -o r543t_recover_linux_x64

./r543t_recover_linux_x64 --self-test
