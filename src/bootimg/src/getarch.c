#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define EI_MAG0         0
#define EI_MAG1         1
#define EI_MAG2         2
#define EI_MAG3         3
#define EI_CLASS        4

#define ELFCLASSNONE    0
#define ELFCLASS32      1
#define ELFCLASS64      2
#define ELFCLASSNUM     3

#define EI_NIDENT		16


int main_getarch(int argc, char** argv)
{
	FILE			*f;
	unsigned char	buffer[EI_NIDENT];	
	int				quiet = 0;
	char			*file = NULL;

	--argc;
	argv++;
	while(argc > 0){
		char *arg = argv[0];
		--argc;
		argv++;
		if (!strcmp(arg, "-q"))
			quiet = 1;
		else if (argc >= 1) {
			char *val = argv[0];
			--argc;
			argv++;
			if (!strcmp(arg, "-i"))
				file = val;
		}
	}

	if (!file) {
		fprintf(stderr, "Usage: getarch -i file [ -q ]\n");
		return 0;
	}

	f = fopen(file, "rb");
	if (f == 0) {
		if (!quiet)
			fprintf(stderr, "Could not open image %s\n\n", file);
		return 0;
	}

	fread(buffer, 1, sizeof(buffer), f);
	fclose(f);

	if (buffer[EI_MAG0 ] != 0x7f ||
		buffer[EI_MAG1] != 'E' ||
		buffer[EI_MAG2] != 'L' ||
		buffer[EI_MAG3] != 'F' ) {
		if (!quiet)
			fprintf(stderr, "No ELF header found\n\n");
		return 0;
	}

	if (buffer[EI_CLASS] == ELFCLASS32)
		return 32;
	
	if (buffer[EI_CLASS] == ELFCLASS64)
		return 64;

	if (!quiet)
		fprintf(stderr, "Unknown elf class %d\n\n", buffer[EI_CLASS]);
	return 0;
}
