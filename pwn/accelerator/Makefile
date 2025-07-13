test.bin: test.asm
	nasm -f bin test.asm -o test.bin

run: test.bin
	./qemu/build/qemu-system-x86_64 -drive if=ide,format=raw,file=test.bin -device coproc -nographic

check:
	gcc test.c -o rootfs/bin/check -static -g
	pwnc kernel compress --initramfs initramfs.cpio.gz --rootfs ./rootfs