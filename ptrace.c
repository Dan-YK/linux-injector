#include <stdio.h>
#include <sys/wait.h>

#include "inject.h"
#include "ptrace.h"

int PtraceAttach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        fprintf(stderr, "[-] Failed to attach to pid %d\n", pid);
        return 0;
    }
    waitpid(pid, NULL, WUNTRACED);

#ifdef DEBUG
    printf("[+] Successfully attached to pid %d\n\n", pid);
#endif

    return 1;
}

int PtraceCont(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        fprintf(stderr, "[-] Failed to continue pid %d\n", pid);
        return 0;
    }

#ifdef DEBUG
    printf("[+] Successfully continued pid %d\n", pid);
#endif

    return 1;
}

int PtraceDetach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        fprintf(stderr, "[-] Failed to detach from pid %d\n", pid);
        return 0;
    }

#ifdef DEBUG
    printf("[+] Successfully detached from pid %d\n", pid);
#endif

    return 1;
}

int PtraceGetRegs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        fprintf(stderr, "[-] Failed to get regs from pid %d\n", pid);
        return 0;
    }

#ifdef DEBUG
    printf("[+] Successfully got regs from pid %d\n", pid);
#endif

    return 1;
}

int PtraceSetRegs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        fprintf(stderr, "[-] Failed to set regs to pid %d\n", pid);
        return 0;
    }

#ifdef DEBUG
    printf("[+] Successfully set regs to pid %d\n", pid);
#endif

    return 1;
}

int PtraceWrite(pid_t pid, uint64_t addr, uint64_t data, size_t size) {
    int loop_count = size / 8;
    uint8_t *tmp_addr = (uint8_t *)addr;
    uint8_t *tmp_data = (uint8_t *)data;
    int mod = size % 8;

    for (int i = 0; i < loop_count; i++) {
        if (ptrace(PTRACE_POKEDATA, pid, tmp_addr, *(uint64_t *)tmp_data) < 0) {
            fprintf(stderr, "[-] Failed to write data to pid %d\n", pid);
            return 0;
        }
        tmp_addr = tmp_addr + 0x8;
        tmp_data = tmp_data + 0x8;
    }
#ifdef DEBUG
    printf("[+] Successfully wrote %s to %lx\n", (char *)data, addr);
#endif

    if (mod > 0) {
        if (ptrace(PTRACE_POKEDATA, pid, tmp_addr, *(uint64_t *)tmp_data) < 0) {
            fprintf(stderr, "[-] Failed to write reamining data to pid %d\n", pid);
            return 0;
        }
#ifdef DEBUG
        printf("[+] Successfully wrote the remaining data to pid %d\n", pid);
#endif
    }

    return 1;
}
