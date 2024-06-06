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
#include <elf.h>
#include <signal.h>
#include <syscall.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

// utils.c
char	*find_exec(char *prog);

#endif
