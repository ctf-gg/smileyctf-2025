#!/bin/sh

set -e

rm -rf obj_dir
verilator +1800-2017ext+sv CPU.h.sv -DSIMULATION -Isrc -o TestBench -CFLAGS -fPIC -cc CPU.sv
cd obj_dir
make -f VCPU.mk
cd ..