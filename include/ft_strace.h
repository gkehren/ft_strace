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

#include "x64_syscall_entry.h"

#define BUFFER_SIZE	1024

typedef struct	s_strace
{
	pid_t				child;
	bool				ignore_syscalls;
	bool				should_print;
	bool				should_print_ret;
	unsigned long long	syscall_count;
} t_strace;

// utils.c
char	*find_exec(char *prog);

// print.c
void	print_syscall(t_strace *strace, const struct syscall_entry *entry, struct user_regs_struct *regs);

#endif
