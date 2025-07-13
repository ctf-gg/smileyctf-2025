#!/usr/local/bin/python
x = input("text: ")
if all((i % 2 != j % 2)*(j % ((i % 4) + 1) == 0) for i,j in enumerate(x.encode())):
    exec(x)