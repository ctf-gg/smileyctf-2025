#!/bin/sh

docker run \
    -w /build \
    -v "$PWD"/qemu:/build/qemu  \
    -v "$PWD"/docker.sh:/build/docker.sh \
    -v "$PWD"/qemu.diff:/build/qemu.diff \
    -v "$PWD"/../bzImage:/build/bzImage \
    -v "$PWD"/../initramfs.cpio.gz:/build/initramfs.cpio.gz \
    -v "$PWD"/../rom_file.mem:/build/rom_file.mem \
    -v "$PWD"/../ram_file.mem:/build/ram_file.mem \
    -it builder \
    /build/qemu/build/qemu-system-x86_64 \
        -kernel ./bzImage \
        -device coproc \
        -initrd ./initramfs.cpio.gz \
        -append "init=/init console=ttyS0 earlycon nokalsr" \
        -m 256M \
        -no-reboot \
        -nographic \
        -monitor /dev/null \
        -s
