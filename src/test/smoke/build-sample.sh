#!/bin/sh
# Regenerates the smoke-test sample from target.c. Freestanding and static, so the host
# toolchain contributes no bytes: no libc, no crt files. Run from anywhere; also
# `./gradlew generateSmokeSample`. Commit the three outputs next to this script.
set -eu
cd "$(dirname "$0")"
CFLAGS="-static -nostdlib -ffreestanding -fno-builtin -fno-stack-protector -fcf-protection=none -fno-asynchronous-unwind-tables -O0 -g0"
# shellcheck disable=SC2086
cc $CFLAGS -o target.bin target.c
# A stripped twin of the same build: fid_build ingests target.bin, fid_apply must put the
# names back on this one.
# shellcheck disable=SC2086
cc $CFLAGS -s -o target-stripped.bin target.c
# An ar archive of the object: the container path of import (one program per member).
# shellcheck disable=SC2086
cc $CFLAGS -c -o target.o target.c
rm -f target.a
ar rcs target.a target.o
rm -f target.o
ls -l target.bin target-stripped.bin target.a
