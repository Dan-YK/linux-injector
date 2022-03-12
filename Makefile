CC=clang
CFLAGS=-ldl
INCLUDE=-I$(PWD)/include

all: clean main

main:
	@$(CC) $(INCLUDE) main.c inject.c ptrace.c -o main $(CFLAGS)

.PHONY: clean
clean:
	@rm -rf main
