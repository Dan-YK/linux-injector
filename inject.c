#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

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

    write_to_remote_memory(remote_pid, remote_mapped_addr, library_path);

    void *handle = call_remote_dlopen(
            local_pid,
            remote_pid,
            remote_mapped_addr,
            RTLD_LAZY | RTLD_LOCAL);
    if (handle <= 0)
        return 0;

    void *s = call_remote_memset(local_pid, remote_pid, remote_mapped_addr, 0x0, 0x100);

    int ret = call_remote_munmap(local_pid, remote_pid, remote_mapped_addr, PAGESIZE);
    printf("ret: %d\n", ret);

    if (ptrace_detach(remote_pid) < 0)
        return 0;

    return 1;
}

void *call_remote_memset(pid_t local_pid, pid_t remote_pid, void *s, int c, size_t n) {
    uint64_t remote_memset_addr = get_remote_func_addr(local_pid, remote_pid, LIBC_PATH, (uint64_t)memset);

    uint8_t argc = 3;
    uint64_t args[argc];
    args[0] = (uint64_t)s;
    args[1] = c;
    args[2] = n;

    uint64_t return_addr = 0xFFFFFFFFFFFFFFFF;
    return (void *)(call_remote_func(remote_pid, remote_memset_addr, return_addr, args, argc));
}


int call_remote_munmap(pid_t local_pid, pid_t remote_pid, void *addr, size_t length) {
    uint64_t remote_munmap_addr = get_remote_func_addr(local_pid, remote_pid, LIBC_PATH, (uint64_t)munmap);

    uint8_t argc = 2;
    uint64_t args[argc];
    args[0] = (uint64_t)addr;
    args[1] = length;

    uint64_t return_addr = 0xFFFFFFFFFFFFFFFF;
    return (int)(call_remote_func(remote_pid, remote_munmap_addr, return_addr, args, argc));
}


void *call_remote_mmap(pid_t local_pid, pid_t remote_pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
#ifdef DEBUG
    log_debug("[+] Calling mmap...");
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
    log_debug("[+] mmap arguments");
    log_debug("[+] addr: %lx", args[0]);
    log_debug("[+] length: %lx", args[1]);
    log_debug("[+] prot: %lx", args[2]);
    log_debug("[+] flags: %lx", args[3]);
    log_debug("[+] fd: %lx", args[4]);
    log_debug("[+] offset: %lx", args[5]);
#endif

    uint64_t return_addr = 0xFFFFFFFFFFFFFFFF;
    return (void *)(call_remote_func(remote_pid, remote_mmap_addr, return_addr, args, argc));
}


uint64_t call_remote_dlopen(pid_t local_pid, pid_t remote_pid, const char *filename, int flags) {
#ifdef DEBUG
    log_debug("[+] Calling dlopen...");
#endif

    uint64_t remote_dlopen_addr = get_remote_func_addr(local_pid, remote_pid, LIBC_PATH, (uint64_t)dlopen);

    uint8_t argc = 2;
    uint64_t args[argc];
    args[0] = filename;
    args[1] = flags;

#ifdef DEBUG
    log_debug("[+] dlopen arguments");
    log_debug("[+] filename: 0x%lx", args[0]);
    log_debug("[+] flags: %lx", args[1]);
#endif

    uint64_t return_addr = 0xFFFFFFFFFFFFFFFF;
    return call_remote_func(remote_pid, remote_dlopen_addr, return_addr, args, argc);
}


uint64_t get_remote_func_addr(pid_t local_pid, pid_t remote_pid, const char *module_name, uint64_t local_function_addr) {
    uint64_t local_module_base_addr = get_module_base_addr(local_pid, module_name);
    uint64_t remote_module_base_addr = get_module_base_addr(remote_pid, module_name);

#ifdef DEBUG
    log_debug("[+] local module base address: 0x%lx", local_module_base_addr);
    log_debug("[+] local function address: 0x%lx", local_function_addr);
    log_debug("[+] offset: 0x%lx", local_function_addr - local_module_base_addr);
    log_debug("[+] remote module base address: 0x%lx", remote_module_base_addr);
    log_debug("[+] remote function address: 0x%lx", remote_module_base_addr + (local_function_addr - local_module_base_addr));
#endif

    return remote_module_base_addr + (local_function_addr - local_module_base_addr);
}


uint64_t get_module_base_addr(pid_t pid, const char *module_name) {
    char line[0x100];
    uint64_t base_addr = 0x0;

    char *file_path = (char *)calloc(0x100, sizeof(char));
    snprintf(file_path, 0x100, "/proc/%d/maps", pid);
    FILE *fp = fopen(file_path, "r");
    if (fp != NULL) {
        while (fgets(line, 0x100, fp) != NULL) {
            if (strstr(line, module_name) != NULL) {
                base_addr = strtoul(strtok(line, "-"), NULL, 16);
                break;
            }
        }
        fclose(fp);
    }
    free(file_path);

    return base_addr;
}


uint64_t call_remote_func(pid_t pid, uint64_t function_addr, uint64_t return_addr, uint64_t *args, size_t argc) {
    struct user_regs_struct regs;
    struct user_regs_struct saved_regs;

    ptrace_getregs(pid, &regs);

    memcpy(&saved_regs, &regs, sizeof(struct user_regs_struct));

    regs.rip = function_addr;
    regs.rsp = regs.rsp - 0x8;
    if (argc == 6) {
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.rcx = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
    }
    else if (argc == 2) {
        regs.rdi = args[0];
        regs.rsi = args[1];
    }


    if (ptrace(PTRACE_POKEDATA, pid, regs.rsp, return_addr) < 0) {
        log_error("[-] Failed to force pid %d to interrupt", pid);
        return 0;
    }
#ifdef DEBUG
    log_debug("[+] Successfully set up return address to pid %d", pid);
#endif

    ptrace_setregs(pid, &regs);

    ptrace_cont(pid);
    waitpid(pid, NULL, WUNTRACED);

    ptrace_getregs(pid, &regs);
    saved_regs.rax = regs.rax;
    ptrace_setregs(pid, &saved_regs);

#ifdef DEBUG
    log_debug("[+] return value: 0x%llx\n", regs.rax);
#endif

    return regs.rax;
}
