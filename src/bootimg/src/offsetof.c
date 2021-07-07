#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

int main_offsetof(int argc, char* argv[])
{
	FILE			*f;
	unsigned char	pattern[128];
	unsigned int	pattern_len, p;
	int				i;
	unsigned char	buffer[406];

	if (argc < 3) {
		fprintf(stderr, "Usage: offsetof <file> <hex pattern>\n\n");
		return 0;
	}

	pattern_len = 0;
	for (i=2; i<argc; i++)
		pattern[pattern_len++]= (unsigned char)strtoul(argv[i], NULL, 16);

	f = fopen(argv[1], "rb");
	if (f == NULL) {
		fprintf(stderr, "Error: Could not open file %s\n\n", argv[1]);
		return 1;
	}

	memset(buffer, 0, sizeof(buffer));
	while (0 != fread(buffer+pattern_len, 1, sizeof(buffer)-pattern_len, f)) {
		for (p=0; p<sizeof(buffer)-pattern_len; p++)
			if (0 == memcmp(buffer+p, pattern, pattern_len))
				printf("%lu\n", ftell(f) -sizeof(buffer) + p);
		memmove(buffer, buffer+sizeof(buffer)-pattern_len, pattern_len);
	}

	fclose(f);
	return 0;
}
