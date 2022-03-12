#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "inject.h"

int inject(pid_t local_pid, pid_t remote_pid, const char *library_path) {

    if (ptrace_attach(remote_pid) < 0) {
        return -1;
    }

    uint64_t handle = CallDlopen(local_pid, remote_pid, library_path);
    if (handle < 0) {
        return -1;
    }

    if (ptrace_detach(remote_pid) < 0) {
        return -1;
    }

    return 0;
}


uint64_t CallMmap(pid_t local_pid, pid_t remote_pid, size_t length) {
#ifdef DEBUG
    printf("[+] Calling mmap...\n");
#endif
    uint64_t remote_mmap_addr = GetRemoteFunctionAddr(local_pid, remote_pid, LIBC_PATH, (uint64_t)dlsym(NULL, "mmap"));

    uint8_t argc = 6;
    uint64_t args[argc];
    args[0] = 0x0;
    args[1] = length;
    args[2] = PROT_READ | PROT_WRITE;
    args[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    args[4] = 0x0;
    args[5] = 0x0;

#ifdef DEBUG
    printf("[+] arg0: %lx\n", args[0]);
    printf("[+] arg1: %lx\n", args[1]);
    printf("[+] arg2: %lx\n", args[2]);
    printf("[+] arg3: %lx\n", args[3]);
    printf("[+] arg4: %lx\n", args[4]);
    printf("[+] arg5: %lx\n", args[5]);
#endif

    uint64_t return_addr = 0xFFFFFFFFFFFFFFFF;
    return CallRemoteFunction(remote_pid, remote_mmap_addr, return_addr, args, argc);
}


uint64_t CallDlopen(pid_t local_pid, pid_t remote_pid, const char *library_path) {

    uint64_t mmap_ret = CallMmap(local_pid, remote_pid, PAGESIZE);

    ptrace_write(remote_pid, mmap_ret, (uint64_t)library_path, strlen(library_path));

#ifdef DEBUG
    printf("[+] Calling dlopen...\n");
#endif
    uint64_t remote_dlopen_addr = GetRemoteFunctionAddr(local_pid, remote_pid, LIBC_PATH, (uint64_t)dlsym(NULL, "dlopen"));

    uint8_t argc = 2;
    uint64_t args[argc];
    args[0] = mmap_ret;
    args[1] = RTLD_LAZY;

    uint64_t return_addr = 0xFFFFFFFFFFFFFFFF;
    return CallRemoteFunction(remote_pid, remote_dlopen_addr, return_addr, args, argc);
}


uint64_t GetRemoteFunctionAddr(pid_t local_pid, pid_t remote_pid, const char *module_name, uint64_t local_function_addr) {
    uint64_t local_base_addr = GetModuleBaseAddr(local_pid, module_name);
    uint64_t remote_base_addr = GetModuleBaseAddr(remote_pid, module_name);

#ifdef DEBUG
    printf("[+] local base address: 0x%lx\n", local_base_addr);
    printf("[+] local function address: 0x%lx\n", local_function_addr);
    printf("[+] offset: 0x%lx\n", local_function_addr - local_base_addr);
    printf("[+] remote base address: 0x%lx\n", remote_base_addr);
    printf("[+] remote function address: 0x%lx\n", remote_base_addr + (local_function_addr - local_base_addr));
#endif

    return remote_base_addr + (local_function_addr - local_base_addr) + 0x2;
}


uint64_t GetModuleBaseAddr(pid_t pid, const char *module_name) {
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

uint64_t CallRemoteFunction(pid_t pid, uint64_t function_addr, uint64_t return_addr, uint64_t *args, size_t argc) {
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
        fprintf(stderr, "[-] Failed to force pid %d to interrupt\n", pid);
        return -1;
    }
#ifdef DEBUG
    printf("[+] Successfully set up return address to pid %d\n", pid);
#endif

    ptrace_setregs(pid, &regs);

    //printf("BEFORE\n");
    //print_registers(&regs);

    ptrace_cont(pid);
    
    waitpid(pid, NULL, WUNTRACED);

    ptrace_getregs(pid, &regs);
    ptrace_setregs(pid, &saved_regs);

    //printf("AFTER\n");
    //print_registers(&regs);
    //print_registers(&saved_regs);
#ifdef DEBUG
    printf("[+] return value: 0x%llx\n\n", regs.rax);
#endif

    return regs.rax;
}

void print_registers(struct user_regs_struct *regs) {
    printf("regs->r15: 0x%llx\n", regs->r15);
    printf("regs->r14: 0x%llx\n", regs->r14);
    printf("regs->r13: 0x%llx\n", regs->r13);
    printf("regs->r12: 0x%llx\n", regs->r12);
    printf("regs->rbp: 0x%llx\n", regs->rbp);
    printf("regs->rbx: 0x%llx\n", regs->rbx);
    printf("regs->r11: 0x%llx\n", regs->r11);
    printf("regs->r10: 0x%llx\n", regs->r10);
    printf("regs->r9: 0x%llx\n", regs->r9);
    printf("regs->r8: 0x%llx\n", regs->r8);
    printf("regs->rax: 0x%llx\n", regs->rax);
    printf("regs->rcx: 0x%llx\n", regs->rcx);
    printf("regs->rdx: 0x%llx\n", regs->rdx);
    printf("regs->rsi: 0x%llx\n", regs->rsi);
    printf("regs->rdi: 0x%llx\n", regs->rdi);
    printf("regs->orig_rax: 0x%llx\n", regs->orig_rax);
    printf("regs->rip: 0x%llx\n", regs->rip);
    printf("regs->cs: 0x%llx\n", regs->cs);
    printf("regs->eflags: 0x%llx\n", regs->eflags);
    printf("regs->rsp: 0x%llx\n", regs->rsp);

    return;
}
