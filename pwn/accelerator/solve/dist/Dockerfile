FROM ubuntu:25.10 as base

RUN apt-get update && \
    apt-get install -y \
        libglib2.0-dev

RUN mkdir -p /build/qemu/coproc /build/qemu/build /build/qemu/share/qemu-firmware/
WORKDIR /build/qemu/
COPY libvcpu.so coproc/
COPY qemu-system-x86_64 build/
COPY firmware /build/qemu/share/qemu-firmware/

WORKDIR /app
COPY rom_file.mem ram_file.mem bzImage initramfs.cpio.gz flag.txt ./
COPY run.sh run
RUN chmod +x run