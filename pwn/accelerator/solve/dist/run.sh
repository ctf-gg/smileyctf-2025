#!/bin/sh

flag=$(mktemp)
cp flag.txt "$flag"

/build/qemu/build/qemu-system-x86_64 \
    -kernel ./bzImage \
    -device coproc \
    -drive format=raw,file="$flag" \
    -initrd ./initramfs.cpio.gz \
    -append "init=/init console=ttyS0 oops=panic loglevel=0 panic_on_warn=1" \
    -m 256M \
    -no-reboot \
    -nographic \
    -monitor /dev/null \
    -s