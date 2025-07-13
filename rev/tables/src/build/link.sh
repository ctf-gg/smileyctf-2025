# echo "Assembling..."
# time nasm -felf64 insn.s -o insn.o
echo "Linking..."
time gcc insn.o main.c -o main -O0 -fno-stack-protector
echo "Stripping..."
time strip main