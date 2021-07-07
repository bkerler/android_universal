#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>

static void hex2byte(const char *hex, unsigned char *str)
{
	char high, low;
	int i = 0, length = strlen(hex);
	for (; i < length; i += 2)
	{
		high = toupper(hex[i]) - '0';
		low = toupper(hex[i + 1]) - '0';
		str[i / 2] = ((high > 9 ? high - 7 : high) << 4) + (low > 9 ? low - 7 : low);
	}
}

int main_hexpatch(int argc, char **argv)
{
	size_t i = 0;
	if (argc != 4)
	{
		fprintf(stderr, "hexpatch requires [filename] [searchhexpattern] [replacehexpattern]\n");
		return 0;
	}

	char *image = argv[1];
	char *from = argv[2];
	char *to = argv[3];

	int patternsize = strlen(from) / 2, patchsize = strlen(to) / 2;
	FILE* f = fopen(image, "r+b");
	if (!f)
	{
		fprintf(stderr,"Could not open file %s for writing\n\n", image);
		return 0;
	}

	fseek(f, 0, SEEK_END);
	size_t filesize = ftell(f);
	if (filesize==0)
	{
		fprintf(stderr, "Sepolicy is empty on %s. Aborting.\n\n", image);
		fclose(f);
		return 0;
	}

	unsigned char *buffer = (unsigned char*)malloc(filesize);
	fseek(f, 0, SEEK_SET);
	fread(buffer, 1, filesize, f);
	fseek(f, 0, SEEK_SET);

	unsigned char* pattern = (unsigned char*)malloc(patternsize);
	unsigned char* patch = (unsigned char*)malloc(patchsize);
	hex2byte(from, pattern);
	hex2byte(to, patch);

	for (; filesize > 0 && i < filesize - patternsize; ++i)
	{
		if (memcmp(buffer + i, pattern, patternsize) == 0)
		{
			fprintf(stderr, "Pattern %s found!\nPatching to %s\n", from, to);
			memset(buffer + i, 0, patternsize);
			memcpy(buffer + i, patch, patchsize);
			i += patternsize - 1;
		}
	}
	fwrite(buffer, 1, filesize, f);
	fclose(f);
	free(buffer);
	free(pattern);
	free(patch);
	return 1;
}
