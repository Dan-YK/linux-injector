#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "inject.h"
#include "log.c/src/log.h"

int main(int argc, const char **argv) {
    if (argc != 3) {
        printf("Usage: %s [process id] [libray path]\n", argv[0]);
        return 1;
    }

    FILE *logger = fopen("logger/my_logger.log", "w");
    log_set_quiet(true);
    log_add_fp(logger, LOG_TRACE);

    const pid_t remote_pid = atoi(argv[1]);
    const char *library_path = argv[2];
    const pid_t local_pid = getpid();

#ifdef DEBUG
    log_debug("[+] remote process id: %d", remote_pid);
    log_debug("[+] library path: %s", library_path);
    log_debug("[+] local process id: %d\n", local_pid);
#endif

    if (!inject(local_pid, remote_pid, library_path)) {
#ifdef DEBUG
        log_error("[-] Failed to inject pid %d with the library, %s!\n", remote_pid, library_path);
#endif
        return 1;
    }

    return 0;
}
