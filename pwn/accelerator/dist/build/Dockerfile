FROM ubuntu:25.10 as build

RUN apt-get update && \
    apt-get install -y \
        gcc g++ make flex cmake meson python3 python3-pip verilator git pkg-config libglib2.0-dev