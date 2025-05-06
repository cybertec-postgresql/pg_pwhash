#include <crypt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	char *pw_hash = crypt_gensalt("$y$", 9, NULL, 0);

	if (argc == 2 && argv[1] != NULL)
	{
		fprintf(stdout, "hashing password\n");
		char *pwd = crypt(argv[1], pw_hash);
		fprintf(stdout, "%s\n", pwd);
	}
	else if (argc == 3 && argv[1] != NULL && argv[2] != NULL)
	{
		fprintf(stdout, "hashing password with salt\n");
		char *pwd = crypt(argv[1], argv[2]);
		fprintf(stdout, "%s\n", pwd);
	}
	else
	{
		int param_N = (int)(*(pw_hash + 2));
		fprintf(stdout, "generating salt\n");
		fprintf(stdout, "%s\n", pw_hash);
		fprintf(stdout, "param_N: %d\n", param_N);
	}
	return 0;
}
