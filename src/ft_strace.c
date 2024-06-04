#include "../include/ft_strace.h"

void	ft_strace(char *prog, char **args)
{
	pid_t	child = fork();

	if (child == 0)
	{
		ptrace(PTRACE_TRACEME, 0, NULL, NULL); // TODO: replace forbidden PTRACE_TRACE
		kill(getpid(), SIGSTOP);
		execv(prog, args);
	}
	else
	{
		int	status;
		waitpid(child, &status, 0);
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

		while (1)
		{
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
			waitpid(child, &status, 0);

			if (WIFEXITED(status) || WIFSIGNALED(status))
				break;

			struct user_regs_struct regs;
			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			printf("syscall(%lld)\n", regs.orig_rax);
		}
	}
}

int	main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("ft_strace: must have PROG [ARGS]\n");
		return (1);
	}
	ft_strace(argv[1], argv + 1);
	return (0);
}
