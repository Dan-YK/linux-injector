#include <stdint.h>
#include <sys/types.h>

#define DEBUG 1

int inject(pid_t local_pid, pid_t remote_pid, const char *library_path);

uint64_t CallDlopen(pid_t local_pid, pid_t remote_pid, const char *library_path);
uint64_t CallMmap(pid_t local_pid, pid_t remote_pid, size_t length);

uint64_t GetModuleBaseAddr(pid_t pid, const char *module_name);
uint64_t GetRemoteFunctionAddr(pid_t local_pid, pid_t remote_pid, const char *module_name, uint64_t local_function_addr);
