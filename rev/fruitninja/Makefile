CFLAGS="-Wl,-T,linker.ld -O1 -flto -fno-inline-functions"

obj_dir/libverilated.a: src/ALU.sv src/Control.sv src/CPU.h.sv src/CPU.sv src/Hazard.sv src/ImmGen.sv src/PC.sv src/RAM.sv src/Register.sv src/WriteBack.sv
	./prep.sh

vcpu: obj_dir/libverilated.a vcpu.cpp
	g++ -Iobj_dir -I/usr/share/verilator/include vcpu.cpp -o vcpu /usr/share/verilator/include/verilated.cpp -lVCPU -Lobj_dir -lverilated -no-pie -O2 -static -flto
	strip vcpu

chall: vcpu src/linker.ld src/gen.c
	cd src; CFLAGS=$(CFLAGS) python3 ../tools/rom.py gen.c ../rom_file.mem ../ram_file.mem

run: chall
	./vcpu

debug:
	cd src; CFLAGS=$(CFLAGS) python3 ../tools/rom.py gen.c --elf chall.elf /dev/null