#ifndef INJECT_H
#define INJECT_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#define LIBC_PATH "/usr/lib/x86_64-linux-gnu/libc.so.6"
#define LIBDL_PATH "/usr/lib/x86_64-linux-gnu/libdl.so.2"
#define PAGESIZE sysconf(_SC_PAGESIZE)

#define DEBUG 1
#define SEGFAULT_RET_ADDR 0xFFFFFFFFFFFFFFFF

int inject(pid_t local_pid, pid_t remote_pid, const char *library_path);

void *call_remote_mmap(pid_t local_pid, pid_t remote_pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void *call_remote_dlopen(pid_t local_pid, pid_t remote_pid, const char *filename, int flags);
void *call_remote_memset(pid_t local_pid, pid_t remote_pid, void *s, int c, size_t n);
int call_remote_munmap(pid_t local_pid, pid_t remote_pid, void *addr, size_t length);

#endif
