build:
	zig cc exploit.c -target x86_64-linux-musl -static -Os -g -no-pie -o exploit.debug -ffunction-sections -fdata-sections -flto
	# gcc exploit.c -static -Os -g -pie -o exploit.debug -flto -ffunction-sections -fdata-sections
	cp exploit.debug exploit
	strip exploit
	cp exploit rootfs/bin/pwn
	pwnc kernel compress