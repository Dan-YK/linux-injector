CC=clang
CFLAGS=-ldl
INCLUDE=-I$(PWD)/include

all: clean main hook

main:
	@$(CC) $(INCLUDE) main.c inject.c ptrace.c -o main $(CFLAGS)

hook:
	@$(CC) -fPIC -shared hook.c -o hook.so

.PHONY: clean
clean:
	@rm -rf main
	@rm -rf hook.so
