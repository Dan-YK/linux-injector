#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "inject.h"
#include "log.c/src/log.h"

int inject(pid_t local_pid, pid_t remote_pid, const char *library_path) {

    if (!ptrace_attach(remote_pid)) {
        return 0;
    }

    uint64_t handle = call_dlopen(local_pid, remote_pid, library_path);
    if (handle < 0) {
        return 0;
    }

    if (ptrace_detach(remote_pid) < 0) {
        return 0;
    }

    return 1;
}


uint64_t call_mmap(pid_t local_pid, pid_t remote_pid, size_t length) {
#ifdef DEBUG
    log_debug("[+] Calling mmap...");
#endif
    uint64_t remote_mmap_addr = get_remote_func_addr(local_pid, remote_pid, LIBC_PATH, (uint64_t)dlsym(NULL, "mmap"));

    uint8_t argc = 6;
    uint64_t args[argc];
    args[0] = 0x0;
    args[1] = length;
    args[2] = PROT_READ | PROT_WRITE;
    args[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    args[4] = 0x0;
    args[5] = 0x0;

#ifdef DEBUG
    log_debug("[+] mmap arguments");
    log_debug("[+] arg0: %lx", args[0]);
    log_debug("[+] arg1: %lx", args[1]);
    log_debug("[+] arg2: %lx", args[2]);
    log_debug("[+] arg3: %lx", args[3]);
    log_debug("[+] arg4: %lx", args[4]);
    log_debug("[+] arg5: %lx", args[5]);
#endif

    uint64_t return_addr = 0xFFFFFFFFFFFFFFFF;
    return call_remote_func(remote_pid, remote_mmap_addr, return_addr, args, argc);
}


uint64_t call_dlopen(pid_t local_pid, pid_t remote_pid, const char *library_path) {

    uint64_t mmap_ret = call_mmap(local_pid, remote_pid, PAGESIZE);

    ptrace_write(remote_pid, mmap_ret, (uint64_t)library_path, strlen(library_path) + 1);

#ifdef DEBUG
    log_debug("[+] Calling dlopen...");
#endif
    uint64_t remote_dlopen_addr = get_remote_func_addr(local_pid, remote_pid, LIBC_PATH, (uint64_t)dlsym(NULL, "dlopen"));

    uint8_t argc = 2;
    uint64_t args[argc];
    args[0] = mmap_ret;
    args[1] = RTLD_LAZY | RTLD_LOCAL;

#ifdef DEBUG
    log_debug("[+] dlopen arguments");
    log_debug("[+] arg0: 0x%lx", args[0]);
    log_debug("[+] arg1: %lx", args[1]);
#endif

    uint64_t return_addr = 0xFFFFFFFFFFFFFFFF;
    return call_remote_func(remote_pid, remote_dlopen_addr, return_addr, args, argc);
}


uint64_t get_remote_func_addr(pid_t local_pid, pid_t remote_pid, const char *module_name, uint64_t local_function_addr) {
    uint64_t local_base_addr = get_module_base_addr(local_pid, module_name);
    uint64_t remote_base_addr = get_module_base_addr(remote_pid, module_name);

#ifdef DEBUG
    log_debug("[+] local base address: 0x%lx", local_base_addr);
    log_debug("[+] local function address: 0x%lx", local_function_addr);
    log_debug("[+] offset: 0x%lx", local_function_addr - local_base_addr);
    log_debug("[+] remote base address: 0x%lx", remote_base_addr);
    log_debug("[+] remote function address: 0x%lx", remote_base_addr + (local_function_addr - local_base_addr));
#endif

    return remote_base_addr + (local_function_addr - local_base_addr);
}


uint64_t get_module_base_addr(pid_t pid, const char *module_name) {
    char line[0x100];
    uint64_t base_addr = 0;

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

void print_regs(struct user_regs_struct *regs) {
#ifdef DEBUG
    log_debug("regs->r15: 0x%llx\n", regs->r15);
    log_debug("regs->r14: 0x%llx\n", regs->r14);
    log_debug("regs->r13: 0x%llx\n", regs->r13);
    log_debug("regs->r12: 0x%llx\n", regs->r12);
    log_debug("regs->rbp: 0x%llx\n", regs->rbp);
    log_debug("regs->rbx: 0x%llx\n", regs->rbx);
    log_debug("regs->r11: 0x%llx\n", regs->r11);
    log_debug("regs->r10: 0x%llx\n", regs->r10);
    log_debug("regs->r9: 0x%llx\n", regs->r9);
    log_debug("regs->r8: 0x%llx\n", regs->r8);
    log_debug("regs->rax: 0x%llx\n", regs->rax);
    log_debug("regs->rcx: 0x%llx\n", regs->rcx);
    log_debug("regs->rdx: 0x%llx\n", regs->rdx);
    log_debug("regs->rsi: 0x%llx\n", regs->rsi);
    log_debug("regs->rdi: 0x%llx\n", regs->rdi);
    log_debug("regs->orig_rax: 0x%llx\n", regs->orig_rax);
    log_debug("regs->rip: 0x%llx\n", regs->rip);
    log_debug("regs->cs: 0x%llx\n", regs->cs);
    log_debug("regs->eflags: 0x%llx\n", regs->eflags);
    log_debug("regs->rsp: 0x%llx\n", regs->rsp);
#endif
    return;
}
