#!/bin/sh

cp -r chall/{bzImage,run.sh,Dockerfile,libvcpu.so,qemu-system-x86_64,firmware} dist
cp rom_file.mem ram_file.mem initramfs.cpio.gz chall
cp rom_file.mem ram_file.mem initramfs.cpio.gz dist