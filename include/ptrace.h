#ifndef PTRACE_H_
#define PTRACE_H_

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

int ptrace_attach(pid_t pid);
int ptrace_cont(pid_t pid);
int ptrace_detach(pid_t pid);
int ptrace_getregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_setregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_write(pid_t pid, uint64_t addr, uint64_t data, size_t size);

#endif
