#ifndef FT_STRACE_H
#define FT_STRACE_H

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <elf.h>
#include <signal.h>
#include <syscall.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <ctype.h>

#include "syscall_entry.h"

#define BUFFER_SIZE	1024
#define SYSCALL_TABLE_SIZE_x64	335
#define SYSCALL_TABLE_SIZE_x32	403

struct user_regs_struct32
{
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t eax;
	uint32_t xds;
	uint32_t xes;
	uint32_t xfs;
	uint32_t xgs;
	uint32_t orig_eax;
	uint32_t eip;
	uint32_t xcs;
	uint32_t eflags;
	uint32_t esp;
	uint32_t xss;
};

typedef union
{
	struct user_regs_struct regs64;
	struct user_regs_struct32 regs32;
}	regs_union;

typedef struct	s_strace
{
	pid_t				child;
	bool				ignore_syscalls;
	bool				should_print;
	bool				should_print_ret;
}	t_strace;

char	*find_exec(char *prog);
void	handle_x64_syscall(t_strace *strace, regs_union *regs);
void	handle_x32_syscall(t_strace *strace, regs_union *regs);
void	print_syscall(t_strace *strace, const struct syscall_entry *entry, regs_union *regs, bool is_x64);

#endif
