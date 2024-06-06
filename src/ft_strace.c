#include "../include/ft_strace.h"

void	block_signals(void)
{
	sigset_t	set;

	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGHUP);
	sigprocmask(SIG_SETMASK, &set, NULL);
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
	int	status;

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
	//if (ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESYSGOOD) < 0)
	//{
	//	fprintf(stderr, "ft_strace: ptrace: %s\n", strerror(errno));
	//	return (1);
	//}
	block_signals();
	waitpid(child, &status, 0);
	return (0);
}

// TODO: for now handle 64-bit syscall later add support for 32-bit syscall
int	handle_syscall(pid_t child)
{
	struct user_regs_struct	regs;
	struct iovec			io;

	io.iov_base = &regs;
	io.iov_len = sizeof(regs);
	if (ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &io) < 0)
	{
		fprintf(stderr, "ft_strace: ptrace: %s\n", strerror(errno));
		return (1);
	}
	fprintf(stderr, "syscall(%lld) = %lld\n", regs.orig_rax, regs.rax);
	return (0);
}

int	ft_strace(char *prog, char **args, char **env)
{
	pid_t		child;
	int			status;
	int			sig;
	siginfo_t	info;

	child = create_child_process(prog, args, env);
	if (child < 0)
		return (1);

	if (init_trace_child(child) != 0)
		return (1);

	while (1)
	{
		if (ptrace(PTRACE_SYSCALL, child, NULL, sig) < 0)
			break;
		if (waitpid(child, &status, 0) < 0)
			break;

		if (!ptrace(PTRACE_GETSIGINFO, child, NULL, &info) && info.si_signo != SIGTRAP)
		{
			// Signal received
			sig = info.si_signo;
			fprintf(stderr, "signal received: %s: %s\n", prog, strsignal(sig));
		}
		else
			sig = 0;

		if (handle_syscall(child) != 0)
			break;
	}

	if (WIFSIGNALED(status))
	{
		fprintf(stderr, "ft_strace: %s: %s\n", prog, strsignal(WTERMSIG(status)));
		kill(getpid(), WTERMSIG(status));
	}
	else
		fprintf(stderr, "ft_strace: %s: exited with status %d\n", prog, WEXITSTATUS(status));
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
