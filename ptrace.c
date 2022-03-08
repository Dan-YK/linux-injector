#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "inject.h"
#include "ptrace.h"

int ptrace_attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        fprintf(stderr, "[-] Failed to attach to pid %d\n", pid);
        return -1;
    }
    waitpid(pid, NULL, WUNTRACED);

#ifdef DEBUG
    printf("[+] Successfully attached to pid %d\n", pid);
#endif

    return 0;
}

int ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        fprintf(stderr, "[-] Failed to detach from pid %d\n", pid);
        return -1;
    }

#ifdef DEBUG
    printf("[+] Successfully detached from pid %d\n", pid);
#endif

    return 0;
}
