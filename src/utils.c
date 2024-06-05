#include "../include/ft_strace.h"

static char	*find_in_path(char *prog)
{
	char	*path = getenv("PATH");
	char	*path_split = strtok(path, ":");
	char	*path_exec = NULL;

	while (path_split != NULL)
	{
		char	*path_prog = malloc(strlen(path_split) + strlen(prog) + 2);
		strcpy(path_prog, path_split);
		strcat(path_prog, "/");
		strcat(path_prog, prog);
		if (access(path_prog, F_OK) == 0)
		{
			path_exec = path_prog;
			break;
		}
		free(path_prog);
		path_split = strtok(NULL, ":");
	}
	return (path_exec);
}

char	*find_exec(char *prog)
{
	if (prog[0] == '/' || prog[0] == '.' || strchr(prog, '/'))
	{
		if (access(prog, F_OK) == 0)
			return (strdup(prog));
		else
			return (NULL);
	}
	return (find_in_path(prog));
}
