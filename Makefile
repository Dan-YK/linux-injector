CC=clang
INCLUDE=-Iinclude

all: clean main

main:
	@$(CC) $(INCLUDE) main.c inject.c ptrace.c -o main

.PHONY: clean
clean:
	@rm -rf main
