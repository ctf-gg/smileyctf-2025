obj-m += coproc.o 

all:
	make -C $(PWD)/../linux M=$(PWD)
	cp coproc.ko ../rootfs
	pwnc kernel compress --initramfs ../initramfs.cpio.gz --rootfs ../rootfs