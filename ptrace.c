#include <stdio.h>
#include <sys/wait.h>

#include "inject.h"
#include "log.c/src/log.h"
#include "ptrace.h"

int ptrace_attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
#ifdef DEBUG
        log_error("[-] Failed to attach to pid %d", pid);
#endif
        return 0;
    }
    waitpid(pid, NULL, WUNTRACED);

#ifdef DEBUG
    log_debug("[+] Successfully attached to pid %d\n", pid);
#endif

    return 1;
}

int ptrace_cont(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
#ifdef DEBUG
        log_error("[-] Failed to continue pid %d", pid);
#endif
        return 0;
    }

#ifdef DEBUG
    log_debug("[+] Successfully continued pid %d", pid);
#endif

    return 1;
}

int ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
#ifdef DEBUG
        log_error("[-] Failed to detach from pid %d", pid);
#endif
        return 0;
    }

#ifdef DEBUG
    log_debug("[+] Successfully detached from pid %d", pid);
#endif

    return 1;
}

int ptrace_getregs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
#ifdef DEBUG
        log_error("[-] Failed to get regs from pid %d", pid);
#endif
        return 0;
    }

#ifdef DEBUG
    log_debug("[+] Successfully got regs from pid %d", pid);
#endif

    return 1;
}

int ptrace_setregs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
#ifdef DEBUG
        log_error("[-] Failed to set regs to pid %d", pid);
#endif
        return 0;
    }

#ifdef DEBUG
    log_debug("[+] Successfully set regs to pid %d", pid);
#endif

    return 1;
}

int ptrace_write(pid_t pid, uint64_t addr, uint64_t data, size_t size) {
    int loop_count = size / 8;
    uint8_t *tmp_addr = (uint8_t *)addr;
    uint8_t *tmp_data = (uint8_t *)data;
    int mod = size % 8;

    for (int i = 0; i < loop_count; i++) {
        if (ptrace(PTRACE_POKEDATA, pid, tmp_addr, *(uint64_t *)tmp_data) < 0) {
#ifdef DEBUG
            log_error("[-] Failed to write data to pid %d", pid);
#endif
            return 0;
        }
        tmp_addr = tmp_addr + 0x8;
        tmp_data = tmp_data + 0x8;
    }
#ifdef DEBUG
    log_debug("[+] Successfully wrote %s to 0x%lx", (char *)data, addr);
#endif

    if (mod > 0) {
        if (ptrace(PTRACE_POKEDATA, pid, tmp_addr, *(uint64_t *)tmp_data) < 0) {
            log_error("[-] Failed to write reamining data to pid %d", pid);
            return 0;
        }
#ifdef DEBUG
        log_debug("[+] Successfully wrote the remaining data to pid %d\n", pid);
#endif
    }

    return 1;
}
