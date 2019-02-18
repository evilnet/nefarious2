#include <stdio.h>
#include <stdlib.h>

char b64map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]";

int main(int argc, char *argv[])
{
	int num = 0;

	if (argc < 2)
	{
		printf("Syntax: %s <numeric>\n", argv[0]);
		return -1;
	}

	num = atoi(argv[1]);

	if ((num < 0) || (num > 4095)) {
		printf("Numeric must be between 0 and 4095\n");
		return -1;
	}

	printf("SID: %c%c\n", b64map[(int)(num >> 6)], b64map[(num & 0x3F)]);

	return 0;
}
