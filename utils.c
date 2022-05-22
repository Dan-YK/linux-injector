#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "inject.h"
#include "log.c/src/log.h"
#include "ptrace.h"
#include "utils.h"


uint64_t get_remote_func_addr(pid_t local_pid, pid_t remote_pid, const char *module_name, uint64_t local_function_addr) {
    uint64_t local_module_base_addr = get_module_base_addr(local_pid, module_name);
    uint64_t remote_module_base_addr = get_module_base_addr(remote_pid, module_name);

#ifdef DEBUG
    log_debug("local module base address: 0x%llx", local_module_base_addr);
    log_debug("local function address: 0x%llx", local_function_addr);
    log_debug("offset: 0x%llx", local_function_addr - local_module_base_addr);
    log_debug("remote module base address: 0x%llx", remote_module_base_addr);
    log_debug("remote function address: 0x%llx", remote_module_base_addr + (local_function_addr - local_module_base_addr));
#endif

    return remote_module_base_addr + (local_function_addr - local_module_base_addr);
}


int write_to_remote_memory(pid_t remote_pid, void *target_addr, const char *payload) {
    int ret = ptrace_write(
            remote_pid,
            (uint64_t)target_addr,
            (uint64_t)payload,
            strlen(payload) + 1);
    if (!ret)
        return 0;

    return 1;
}


void print_regs(struct user_regs_struct *regs) {
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
    return;
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
        log_error("Failed to force pid %d to interrupt", pid);
        return 0;
    }
#ifdef DEBUG
    log_debug("Successfully set up return address to pid %d", pid);
#endif

    ptrace_setregs(pid, &regs);

    ptrace_cont(pid);
    waitpid(pid, NULL, WUNTRACED);

    ptrace_getregs(pid, &regs);
    saved_regs.rax = regs.rax;
    ptrace_setregs(pid, &saved_regs);

#ifdef DEBUG
    log_info("return value: 0x%llx\n", regs.rax);
#endif

    return regs.rax;
}
