#!/bin/sh

zig build-exe -target x86_64-freestanding-none /app/run.zig -ffunction-sections -fdata-sections --gc-sections -OReleaseFast -femit-bin=main --compress-debug-sections=none
python3 fixup.py