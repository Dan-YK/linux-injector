#ifndef INJECT_H_
#define INJECT_H_

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "ptrace.h"

#define LIBC_PATH "/usr/lib/x86_64-linux-gnu/libc.so.6"
#define LIBDL_PATH "/usr/lib/x86_64-linux-gnu/libdl.so.2"
#define PAGESIZE sysconf(_SC_PAGESIZE)

#define DEBUG 1

int inject(pid_t local_pid, pid_t remote_pid, const char *library_path);
uint64_t CallDlopen(pid_t local_pid, pid_t remote_pid, const char *library_path);
uint64_t CallMmap(pid_t local_pid, pid_t remote_pid, size_t length);
uint64_t CallRemoteFunction(pid_t pid, uint64_t function_addr, uint64_t return_addr, uint64_t *args, size_t argc);
uint64_t GetModuleBaseAddr(pid_t pid, const char *module_name);
uint64_t GetRemoteFunctionAddr(pid_t local_pid, pid_t remote_pid, const char *module_name, uint64_t local_function_addr);
void PrintRegisters(struct user_regs_struct *regs);

#endif
