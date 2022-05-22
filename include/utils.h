#ifndef UTILS_H
#define UTILS_H

uint64_t call_remote_func(pid_t pid, uint64_t function_addr, uint64_t return_addr, uint64_t *args, size_t argc);
uint64_t get_module_base_addr(pid_t pid, const char *module_name);
uint64_t get_remote_func_addr(pid_t local_pid, pid_t remote_pid, const char *module_name, uint64_t local_function_addr);
void print_regs(struct user_regs_struct *regs);
void write_to_remote_memory(pid_t remote_pid, void *target_addr, const char *payload);

#endif
