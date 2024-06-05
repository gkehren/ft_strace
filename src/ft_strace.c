#include "../include/ft_strace.h"

int	ft_strace(char *prog, char **args, char **env)
{
	pid_t	child = fork();

	if (child < 0)
	{
		fprintf(stderr, "ft_strace: fork: %s\n", strerror(errno));
		return (1);
	}

	if (child == 0)
	{
		// Child process
		raise(SIGSTOP);
		execve(prog, args, env);
		fprintf(stderr, "ft_strace: execve: %s\n", strerror(errno));
		exit(1);
	}
	else
	{
		// Parent process
		int	status;

		// Seize the child process
		if (ptrace(PTRACE_SEIZE, child, NULL, NULL) < 0)
		{
			fprintf(stderr, "ft_strace: ptrace: %s\n", strerror(errno));
			return (1);
		}
		// Send a signal to interrupt the child
		if (ptrace(PTRACE_INTERRUPT, child, NULL, NULL) < 0)
		{
			fprintf(stderr, "ft_strace: ptrace: %s\n", strerror(errno));
			return (1);
		}

		// Set the child process to trace system calls
		if (ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESYSGOOD) < 0)
		{
			fprintf(stderr, "ft_strace: ptrace: %s\n", strerror(errno));
			return (1);
		}

		// TODO: Block signals and display the complete name of the syscall
		while (1)
		{
			if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0)
				break;
			if (waitpid(child, &status, 0) < 0)
				break;

			if (WIFEXITED(status) || WIFSIGNALED(status))
				break;

			struct user_regs_struct regs;
			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			printf("syscall(%lld)\n", regs.orig_rax);
		}
	}
	return (0);
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
