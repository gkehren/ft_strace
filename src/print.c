#include "../include/ft_strace.h"

void	print_escaped_string(const char *str)
{
	while (*str)
	{
		if (*str == '\n')
			fprintf(stderr, "\\n");
		else if (*str == '\t')
			fprintf(stderr, "\\t");
		else if (*str == '\r')
			fprintf(stderr, "\\r");
		else if (*str == '\b')
			fprintf(stderr, "\\b");
		else if (*str == '\f')
			fprintf(stderr, "\\f");
		else if (*str == '\v')
			fprintf(stderr, "\\v");
		else if (*str == '\\')
			fprintf(stderr, "\\\\");
		else if (*str == '\"')
			fprintf(stderr, "\\\"");
		else if (isprint(*str))
			fputc(*str, stderr);
		else
			fprintf(stderr, "\\x%02x", (unsigned char)*str);
		str++;
	}
}

void	print_str(pid_t child, unsigned long long arg)
{
	char	buffer[BUFFER_SIZE];
	char	mem_path[64];
	snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", child);

	int mem_fd = open(mem_path, O_RDONLY);
	if (mem_fd < 0)
	{
		fprintf(stderr, "ft_strace: open: %s\n", strerror(errno));
		return;
	}

	if (lseek(mem_fd, arg, SEEK_SET) == (off_t)-1)
	{
		fprintf(stderr, "ft_strace: lseek: %s\n", strerror(errno));
		close(mem_fd);
		return;
	}

	ssize_t bytes_read = read(mem_fd, buffer, sizeof(buffer) - 1);
	if (bytes_read < 0)
	{
		fprintf(stderr, "ft_strace: read: %s\n", strerror(errno));
		close(mem_fd);
		return;
	}

	buffer[bytes_read] = '\0';
	fprintf(stderr, "\"");
	print_escaped_string(buffer);
	fprintf(stderr, "\"");
	close(mem_fd);
}

void	print_argv(pid_t child, unsigned long long arg)
{
	fprintf(stderr, "[");
	unsigned long long *argv = (unsigned long long *)arg;
	for (int j = 0; argv[j]; j++)
	{
		if (j > 0)
			fprintf(stderr, ", ");
		print_str(child, argv[j]);
	}
	fprintf(stderr, "]");
}

int count_envp(pid_t child, unsigned long long addr, bool is_x64)
{
	int					count = 0;
	unsigned long long	ptr64;
	unsigned int		ptr32;
	char				mem_path[64];
	snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", child);

	int mem_fd = open(mem_path, O_RDONLY);
	if (mem_fd < 0)
	{
		fprintf(stderr, "ft_strace: open: %s\n", strerror(errno));
		return 0;
	}

	while (1)
	{
		if (is_x64)
		{
			if (pread(mem_fd, &ptr64, sizeof(ptr64), addr + count * sizeof(ptr64)) != sizeof(ptr64))
				break;
			if (ptr64 == 0)
				break;
		}
		else
		{
			if (pread(mem_fd, &ptr32, sizeof(ptr32), addr + count * sizeof(ptr32)) != sizeof(ptr32))
				break;
			if (ptr32 == 0)
				break;
		}
		count++;
	}

	close(mem_fd);
	return count;
}

void	print_flags_open(unsigned long long arg)
{
	int first = 1;

	if ((arg & O_ACCMODE) == O_RDONLY)
	{
		fprintf(stderr, "O_RDONLY");
		first = 0;
	}
	else if ((arg & O_ACCMODE) == O_WRONLY)
	{
		fprintf(stderr, "O_WRONLY");
		first = 0;
	}
	else if ((arg & O_ACCMODE) == O_RDWR)
	{
		fprintf(stderr, "O_RDWR");
		first = 0;
	}

	#define FLAG(flag) if (arg & flag) { if (!first) fprintf(stderr, "|"); fprintf(stderr, #flag); first = 0; }
	FLAG(O_CREAT)
	FLAG(O_EXCL)
	FLAG(O_NOCTTY)
	FLAG(O_TRUNC)
	FLAG(O_APPEND)
	FLAG(O_NONBLOCK)
	FLAG(O_DSYNC)
	FLAG(O_SYNC)
	FLAG(O_RSYNC)
	FLAG(O_DIRECTORY)
	FLAG(O_NOFOLLOW)
	FLAG(O_CLOEXEC)
	FLAG(O_ASYNC)
	FLAG(O_DIRECT)
	FLAG(O_LARGEFILE)
	FLAG(O_NOATIME)
	FLAG(O_PATH)
	FLAG(O_TMPFILE)
	#undef FLAG

	if (first)
		fprintf(stderr, "0");
}

void	print_flags_mmap(unsigned long long arg)
{
	int first = 1;

	#define FLAG(flag) if (arg & flag) { if (!first) fprintf(stderr, "|"); fprintf(stderr, #flag); first = 0; }
	FLAG(MAP_SHARED)
	FLAG(MAP_PRIVATE)
	FLAG(MAP_32BIT)
	FLAG(MAP_ANONYMOUS)
	FLAG(MAP_DENYWRITE)
	FLAG(MAP_EXECUTABLE)
	FLAG(MAP_FILE)
	FLAG(MAP_FIXED)
	FLAG(MAP_FIXED_NOREPLACE)
	FLAG(MAP_GROWSDOWN)
	FLAG(MAP_HUGETLB)
	FLAG(MAP_HUGE_2MB)
	FLAG(MAP_HUGE_1GB)
	FLAG(MAP_LOCKED)
	FLAG(MAP_NONBLOCK)
	FLAG(MAP_NORESERVE)
	FLAG(MAP_POPULATE)
	FLAG(MAP_STACK)
	FLAG(MAP_SYNC)
	FLAG(MAP_UNINITIALIZED)
	#undef FLAG

	if (first)
		fprintf(stderr, "0");
}

void	print_flags_prot(unsigned long long arg)
{
	int first = 1;

	#define FLAG(flag) if (arg & flag) { if (!first) fprintf(stderr, "|"); fprintf(stderr, #flag); first = 0; }
	FLAG(PROT_EXEC)
	FLAG(PROT_READ)
	FLAG(PROT_WRITE)
	FLAG(PROT_NONE)
	#undef FLAG

	if (first)
		fprintf(stderr, "0");
}

void	print_syscall(t_strace *strace, const struct syscall_entry *entry, regs_union *regs, bool is_x64)
{
	fprintf(stderr, "%s(", entry->name);

	for (int i = 0; i < entry->arg_count; i++)
	{
		unsigned long long arg;
		if (is_x64)
		{
			switch (i)
			{
				case 0: arg = regs->regs64.rdi; break;
				case 1: arg = regs->regs64.rsi; break;
				case 2: arg = regs->regs64.rdx; break;
				case 3: arg = regs->regs64.r10; break;
				case 4: arg = regs->regs64.r8; break;
				case 5: arg = regs->regs64.r9; break;
				default: arg = 0; break;
			}
		}
		else
		{
			switch (i)
			{
				case 0: arg = regs->regs32.ebx; break;
				case 1: arg = regs->regs32.ecx; break;
				case 2: arg = regs->regs32.edx; break;
				case 3: arg = regs->regs32.esi; break;
				case 4: arg = regs->regs32.edi; break;
				case 5: arg = regs->regs32.ebp; break;
				default: arg = 0; break;
			}
		}

		if (entry->args[i] == INT || entry->args[i] == LONG || entry->args[i] == ULONG)
			fprintf(stderr, "%lld", arg);
		else if (entry->args[i] == STR)
			print_str(strace->child, arg);
		else if (entry->args[i] == PTR)
		{
			if (arg == 0)
				fprintf(stderr, "NULL");
			else
				fprintf(stderr, "%#llx", arg);
		}
		else if (entry->args[i] == ARGV)
			print_argv(strace->child, arg);
		else if (entry->args[i] == ENVP)
			fprintf(stderr, "%#llx /* %d vars */", arg, count_envp(strace->child, arg, is_x64));
		else if (entry->args[i] == SIGNAL)
		{
			if (arg < NSIG)
				fprintf(stderr, "%s", strsignal(arg));
			else
				fprintf(stderr, "%lld", arg);
		}
		else if (entry->args[i] == FLAG_OPEN)
			print_flags_open(arg);
		else if (entry->args[i] == FLAG_MMAP)
			print_flags_mmap(arg);
		else if (entry->args[i] == FLAG_PROT)
			print_flags_prot(arg);
		else
			fprintf(stderr, "%#llx", arg);
		if (i < entry->arg_count - 1)
			fprintf(stderr, ", ");
	}
	fprintf(stderr, ")");
}
