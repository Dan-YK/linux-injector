#include <dlfcn.h>
//#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
//#include <sys/types.h>
//#include <sys/wait.h>

#include "inject.h"
#include "log.c/src/log.h"
#include "ptrace.h"
#include "utils.h"

int inject(pid_t local_pid, pid_t remote_pid, const char *library_path) {

    if (!ptrace_attach(remote_pid))
        return 0;

    void *remote_mapped_addr = call_remote_mmap(
            local_pid,
            remote_pid,
            NULL,
            PAGESIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            0x0,
            0x0);

    int ret = write_to_remote_memory(remote_pid, remote_mapped_addr, library_path);
    if (!ret) {
#ifdef DEBUG
        log_error("Failed to write to the memory");
#endif
        return 0;
    }

    void *handle = call_remote_dlopen(
            local_pid,
            remote_pid,
            remote_mapped_addr,
            RTLD_LAZY | RTLD_LOCAL);
    if (!handle)
        return 0;

    //void *s = call_remote_memset(local_pid, remote_pid, remote_mapped_addr, 0x0, 0x100);

    ret = call_remote_munmap(local_pid, remote_pid, remote_mapped_addr, PAGESIZE);

    if (ptrace_detach(remote_pid) < 0)
        return 0;

    return 1;
}


void *call_remote_mmap(pid_t local_pid, pid_t remote_pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
#ifdef DEBUG
    log_info("Calling mmap");
#endif

    uint64_t remote_mmap_addr = get_remote_func_addr(local_pid, remote_pid, LIBC_PATH, (uint64_t)mmap);

    uint8_t argc = 6;
    uint64_t args[argc];
    args[0] = (uint64_t)addr;
    args[1] = length;
    args[2] = prot;
    args[3] = flags;
    args[4] = fd;
    args[5] = offset;

#ifdef DEBUG
    log_info("addr: 0x%llx", args[0]);
    log_info("length: 0x%llx", args[1]);
    log_info("prot: 0x%llx", args[2]);
    log_info("flags: 0x%llx", args[3]);
    log_info("fd: 0x%llx", args[4]);
    log_info("offset: 0x%llx", args[5]);
#endif

    return (void *)call_remote_func(remote_pid, remote_mmap_addr, SEGFAULT_RET_ADDR, args, argc);
}


void *call_remote_dlopen(pid_t local_pid, pid_t remote_pid, const char *filename, int flags) {
#ifdef DEBUG
    log_info("Calling dlopen");
#endif

    uint64_t remote_dlopen_addr = get_remote_func_addr(local_pid, remote_pid, LIBC_PATH, (uint64_t)dlopen);

    uint8_t argc = 2;
    uint64_t args[argc];
    args[0] = (uint64_t)filename;
    args[1] = flags;

#ifdef DEBUG
    log_info("filename: 0x%llx", args[0]);
    log_info("flags: 0x%llx", args[1]);
#endif

    return (void *)call_remote_func(remote_pid, remote_dlopen_addr, SEGFAULT_RET_ADDR, args, argc);
}


void *call_remote_memset(pid_t local_pid, pid_t remote_pid, void *s, int c, size_t n) {
#ifdef DEBUG
    log_info("Calling memset");
#endif

    uint64_t remote_memset_addr = get_remote_func_addr(local_pid, remote_pid, LIBC_PATH, (uint64_t)memset);

    uint8_t argc = 3;
    uint64_t args[argc];
    args[0] = (uint64_t)s;
    args[1] = c;
    args[2] = n;

#ifdef DEBUG
    log_info("s: 0x%llx", s);
    log_info("c: 0x%llx", c);
    log_info("n: 0x%llx", n);
#endif

    return (void *)call_remote_func(remote_pid, remote_memset_addr, SEGFAULT_RET_ADDR, args, argc);
}


int call_remote_munmap(pid_t local_pid, pid_t remote_pid, void *addr, size_t length) {
#ifdef DEBUG
    log_info("Calling munmap");
#endif

    uint64_t remote_munmap_addr = get_remote_func_addr(local_pid, remote_pid, LIBC_PATH, (uint64_t)munmap);

    uint8_t argc = 2;
    uint64_t args[argc];
    args[0] = (uint64_t)addr;
    args[1] = length;

#ifdef DEBUG
    log_info("addr: 0x%llx", args[0]);
    log_info("length: 0x%llx", args[1]);
#endif

    return (int)call_remote_func(remote_pid, remote_munmap_addr, SEGFAULT_RET_ADDR, args, argc);
}
