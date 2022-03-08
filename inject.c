#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "inject.h"
#include "ptrace.h"

int inject(pid_t local_pid, pid_t remote_pid, const char *library_path) {
    if (ptrace_attach(remote_pid) < 0) {
        return -1;
    }

    uint64_t mmap_ret = CallMmap(local_pid, remote_pid, 0x400);


    if (ptrace_detach(remote_pid) < 0) {
        return -1;
    }


    return 0;
}

uint64_t CallDlopen(pid_t local_pid, pid_t remote_pid, const char *library_path) {


    return 0;
}


uint64_t CallMmap(pid_t local_pid, pid_t remote_pid, size_t length) {
    uint64_t function_addr = GetRemoteFunctionAddr(local_pid, remote_pid, "libc", ((uint64_t)(void *)mmap));
}


uint64_t GetRemoteFunctionAddr(pid_t local_pid, pid_t remote_pid, const char *module_name, uint64_t local_function_addr) {
    uint64_t local_base_addr = GetModuleBaseAddr(local_pid, module_name);
    uint64_t remote_base_addr = GetModuleBaseAddr(remote_pid, module_name);


#ifdef DEBUG
    printf("[+] local base address: %lx\n", local_base_addr);
    printf("[+] remote base address: %lx\n", remote_base_addr);
#endif


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
                //char *temp_base_addr = strtok(line, "-");
                base_addr = strtoul(strtok(line, "-"), NULL, 16);
                //base_addr = strtoul(base_addr, NULL, 16);
                break;
            }
        }
        fclose(fp);
    }
    free(file_path);
    return base_addr;
}
