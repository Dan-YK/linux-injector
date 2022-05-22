#ifndef UTILS_H_
#define UTILS_H_

void print_regs(struct user_regs_struct *regs);
void write_to_remote_memory(pid_t remote_pid, void *target_addr, const char *payload);

#endif
