#ifndef INJECT_H_
#define INJECT_H_

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#define LIBC_PATH "/usr/lib/x86_64-linux-gnu/libc.so.6"
#define LIBDL_PATH "/usr/lib/x86_64-linux-gnu/libdl.so.2"
#define PAGESIZE sysconf(_SC_PAGESIZE)

#define DEBUG 1

int inject(pid_t local_pid, pid_t remote_pid, const char *library_path);

void *call_remote_mmap(pid_t local_pid, pid_t remote_pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
uint64_t call_remote_dlopen(pid_t local_pid, pid_t remote_pid, const char *filename, int flags);
void *call_remote_memset(pid_t local_pid, pid_t remote_pid, void *s, int c, size_t n);
int call_remote_munmap(pid_t local_pid, pid_t remote_pid, void *addr, size_t length);


uint64_t call_remote_func(pid_t pid, uint64_t function_addr, uint64_t return_addr, uint64_t *args, size_t argc);
uint64_t get_module_base_addr(pid_t pid, const char *module_name);
uint64_t get_remote_func_addr(pid_t local_pid, pid_t remote_pid, const char *module_name, uint64_t local_function_addr);

#endif
