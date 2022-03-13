#ifndef PTRACE_H_
#define PTRACE_H_

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

int PtraceAttach(pid_t pid);
int PtraceCont(pid_t pid);
int PtraceDetach(pid_t pid);
int PtraceGetRegs(pid_t pid, struct user_regs_struct *regs);
int PtraceSetRegs(pid_t pid, struct user_regs_struct *regs);
int PtraceWrite(pid_t pid, uint64_t addr, uint64_t data, size_t size);

#endif
