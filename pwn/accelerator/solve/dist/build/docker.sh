#!/bin/sh

set -e

cd /build/qemu/coproc
if [ ! -d obj_dir ]; then
    ./prep.sh
fi
make vcpu

cd /build/qemu
git apply ../qemu.diff || true

if [ ! -d build ]; then
    mkdir -p build
    cd build
    ../configure --target-list=x86_64-softmmu --extra-cflags="-Wno-error"
    cd ..
fi

cd build
make -j4