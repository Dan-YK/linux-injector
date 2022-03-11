#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "inject.h"

int main(int argc, const char **argv) {
    if (argc != 3) {
        printf("Usage: %s [process id] [libray path]\n", argv[0]);
        return -1;
    }

    const pid_t remote_pid = atoi(argv[1]);
    const char *library_path = argv[2];
    const pid_t local_pid = getpid();

#ifdef DEBUG
    printf("[+] remote process id: %d\n", remote_pid);
    printf("[+] library path: %s\n", library_path);
    printf("[+] local process id: %d\n\n", local_pid);
#endif

    if (inject(local_pid, remote_pid, library_path) < 0) {
        fprintf(stderr, "[-] Failed to inject pid %d with the library, %s!\n", remote_pid, library_path);
        return -1;
    }

    return 0;
}
