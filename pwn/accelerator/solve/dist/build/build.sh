#!/bin/sh

set -e

docker build . -t builder
docker run \
    -w /build \
    -v "$PWD"/qemu:/build/qemu  \
    -v "$PWD"/docker.sh:/build/docker.sh \
    -v "$PWD"/qemu.diff:/build/qemu.diff \
    -it builder /build/docker.sh