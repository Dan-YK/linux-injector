CC=clang
CFLAGS=-ldl
INCLUDE=-I$(PWD)/include
INCLUDE+=-I$(PWD)/log.c/src

all: clean check-and-reinit-submodules main hook

main:
	@$(CC) $(INCLUDE) main.c inject.c ptrace.c log.c/src/log.c -o main $(CFLAGS)

hook:
	@$(CC) -fPIC -shared hook.c -o hook.so

.PHONY: check-and-reinit-submodules clean
check-and-reinit-submodules:
	@if git submodule status | egrep -q '^[-]|^[+]' ; then \
		echo "INFO: Need to reinitialize git submodules";  \
		git submodule update --init; \
	fi

clean:
	@rm -rf main
	@rm -rf hook.so
