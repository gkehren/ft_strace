#include "../include/ft_strace.h"

void	ft_strace(char *prog, char **args, char **env)
{
	pid_t	child = fork();

	if (child == 0)
	{
		// Child process
		kill(getpid(), SIGSTOP); // Stop the child process to allow the parent to seize it
		execve(prog, args, env);
	}
	else
	{
		// Parent process
		int	status;
		waitpid(child, &status, WUNTRACED); // Wait for the child to stop itself

		// Seize the child process
		ptrace(PTRACE_SEIZE, child, NULL, NULL);
		// Send a signal to interrupt the child
		ptrace(PTRACE_INTERRUPT, child, NULL, NULL);
		waitpid(child, &status, 0);

		// Set the child process to trace system calls
		ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESYSGOOD);

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
	ft_strace(path_exec, &argv[1], env);
	free(path_exec);
	return (0);
}
