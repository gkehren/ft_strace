#include "../include/ft_strace.h"

void	handle_x64_syscall(t_strace *strace, regs_union *regs)
{
	static const struct syscall_entry syscall_table[] = SYSCALL_TABLE_x64;

	if (!strace->ignore_syscalls || !strcmp(syscall_table[regs->regs64.orig_rax].name, "execve"))
	{
		if (strace->should_print && !strace->should_print_ret && regs->regs64.rax == (unsigned long long)-ENOSYS && regs->regs64.orig_rax < SYSCALL_TABLE_SIZE_x64)
		{
			strace->should_print_ret = true;
			print_syscall(strace, &syscall_table[regs->regs64.orig_rax], regs, true);
		}
		else
		{
			if (strace->should_print && strace->should_print_ret)
			{
				strace->should_print_ret = false;
				strace->ignore_syscalls = false;

				if (syscall_table[regs->regs64.orig_rax].return_type == INT)
					fprintf(stderr, ") = %lld\n", regs->regs64.rax);
				else
					fprintf(stderr, ") = %#llx\n", regs->regs64.rax);
			}
			else if (strace->ignore_syscalls && (int)regs->regs64.rax < 0)
				strace->should_print = false;
		}
	}

	if (strace->is_x64 == false)
	{
		fprintf(stderr, "[ Process PID=%d runs in 64 bit mode. ]\n", strace->child);
		strace->is_x64 = true;
	}
}

void	handle_x32_syscall(t_strace *strace, regs_union *regs)
{
	static const struct syscall_entry syscall_table[] = SYSCALL_TABLE_x32;

	if (strace->should_print && !strace->should_print_ret && regs->regs32.eax == (unsigned int)-ENOSYS && regs->regs32.orig_eax < SYSCALL_TABLE_SIZE_x32)
	{
		strace->should_print_ret = true;
		strace->orig_eax = regs->regs32.orig_eax;
		print_syscall(strace, &syscall_table[strace->orig_eax], regs, false);
	}
	else
	{
		if (strace->should_print && strace->should_print_ret)
		{
			strace->should_print_ret = false;
			strace->ignore_syscalls = false;

			if (syscall_table[strace->orig_eax].return_type == INT)
				fprintf(stderr, ") = %d\n", regs->regs32.eax);
			else
				fprintf(stderr, ") = %#lx\n", (unsigned long)regs->regs32.eax);
		}
		else if (strace->ignore_syscalls && (int)regs->regs32.eax < 0)
			strace->should_print = false;
	}

	if (strace->is_x64 == true)
	{
		fprintf(stderr, "[ Process PID=%d runs in 32 bit mode. ]\n", strace->child);
		strace->is_x64 = false;
	}
}
