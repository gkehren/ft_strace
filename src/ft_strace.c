#include "../include/ft_strace.h"

const struct syscall_entry syscall_table[] = SYSCALL_TABLE;

void	block_signals(pid_t child)
{
	sigset_t	set;
	int			status;

	sigemptyset(&set);
	sigprocmask(SIG_SETMASK, &set, NULL);
	waitpid(child, &status, 0);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGPIPE);
	sigaddset(&set, SIGHUP);
	sigprocmask(SIG_BLOCK, &set, NULL);
}

pid_t	create_child_process(char *prog, char **args, char **env)
{
	pid_t	child = fork();

	if (child < 0)
	{
		fprintf(stderr, "ft_strace: fork: %s\n", strerror(errno));
		return (-1);
	}
	else if (child == 0)
	{
		// Child process
		raise(SIGSTOP);
		execve(prog, args, env);
		fprintf(stderr, "ft_strace: execve: %s\n", strerror(errno));
		exit(1);
	}
	return (child);
}

int	init_trace_child(pid_t child)
{
	if (ptrace(PTRACE_SEIZE, child, NULL, NULL) < 0)
	{
		fprintf(stderr, "ft_strace: ptrace: %s\n", strerror(errno));
		return (1);
	}
	if (ptrace(PTRACE_INTERRUPT, child, NULL, NULL) < 0)
	{
		fprintf(stderr, "ft_strace: ptrace: %s\n", strerror(errno));
		return (1);
	}
	block_signals(child);
	return (0);
}

void	handle_x64_syscall(t_strace *strace, struct user_regs_struct *regs)
{
	if (!strace->ignore_syscalls || !strcmp(syscall_table[regs->orig_rax].name, "execve"))
	{
		if (strace->should_print && !strace->should_print_ret && regs->rax == (unsigned long long)-ENOSYS && regs->orig_rax < strace->syscall_count)
		{
			strace->should_print_ret = true;
			print_syscall(strace, &syscall_table[regs->orig_rax], regs);
		}
		else
		{
			if (strace->should_print && strace->should_print_ret)
			{
				strace->should_print_ret = false;
				strace->ignore_syscalls = false;
				if (syscall_table[regs->orig_rax].return_type == INT)
					fprintf(stderr, " = %lld\n", regs->rax);
				else
					fprintf(stderr, " = %#llx\n", regs->rax);
			}
			else if (strace->ignore_syscalls && (int)regs->rax < 0)
				strace->should_print = false;
		}
	}
}

// TODO: for now handle 64-bit syscall later add support for 32-bit syscall
int	handle_syscall(t_strace *strace)
{
	struct user_regs_struct	regs;
	struct iovec			io;

	io.iov_base = &regs;
	io.iov_len = sizeof(regs);
	if (ptrace(PTRACE_GETREGSET, strace->child, NT_PRSTATUS, &io) < 0)
		return (1);
	handle_x64_syscall(strace, &regs);
	return (0);
}

int	ft_strace(char *prog, char **args, char **env)
{
	t_strace	strace;
	int			status;
	int			sig = 0;
	siginfo_t	info;

	strace.ignore_syscalls = true;
	strace.should_print = true;
	strace.should_print_ret = false;
	strace.syscall_count = sizeof(syscall_table) / sizeof(syscall_table[0]);
	strace.child = create_child_process(prog, args, env);
	if (strace.child < 0)
		return (1);

	if (init_trace_child(strace.child) != 0)
		return (1);

	while (1)
	{
		if (ptrace(PTRACE_SYSCALL, strace.child, NULL, sig) < 0)
			break;
		if (waitpid(strace.child, &status, 0) < 0)
			break;

		if (!strace.ignore_syscalls && !ptrace(PTRACE_GETSIGINFO, strace.child, NULL, &info) && info.si_signo != SIGTRAP)
		{
			// Signal received
			sig = info.si_signo;
			fprintf(stderr, "signal received: %s: %s\n", prog, strsignal(sig));
		}
		else
			sig = 0;

		if (handle_syscall(&strace) != 0)
			break;
	}

	if (!strace.ignore_syscalls && strace.should_print && strace.should_print_ret)
		fprintf(stderr, " = ?\n");

	if (WIFSIGNALED(status))
	{
		fprintf(stderr, "+++ killed by %s +++\n", strsignal(WTERMSIG(status)));
		kill(getpid(), WTERMSIG(status));
	}
	else
		fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
	return (WEXITSTATUS(status));
}

int	main(int argc, char **argv, char **env)
{
	if (argc < 2)
	{
		fprintf(stderr, "ft_strace: must have PROG [ARGS]\n");
		return (1);
	}
	char *path_exec = find_exec(argv[1]);
	if (path_exec == NULL)
	{
		fprintf(stderr, "ft_strace: %s: command not found\n", argv[1]);
		return (1);
	}
	int ret = ft_strace(path_exec, &argv[1], env);
	free(path_exec);
	return (ret);
}
