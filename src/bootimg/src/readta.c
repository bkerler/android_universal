#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

static const unsigned char magic[] = { 0xc1, 0xe9, 0xf8, 0x3b }; 

int readta_quiet = 0;
FILE *f_readta = NULL;
unsigned char* TA = NULL;

#define TA_PARTITION_SIZE 0x20000

void readta_die(int rc, const char *why, ...)
{
	if (!readta_quiet) {
		va_list ap;
		va_start(ap, why);
		fprintf(stderr,"error: ");
		vfprintf(stderr, why, ap);
		fprintf(stderr,"\n");
		va_end(ap);
	}

	if (TA)
		free(TA);

	if (f_readta)
		fclose(f_readta);

	exit(rc);
}

int readta_usage()
{
	fprintf(stderr, "Usage: readta -i <ta image or partition> -u <unit> [ -o <output file> -q ]\n\n");
	return 1;
}

int main_readta(int argc, char* argv[])
{
	size_t	tasize, pos;
	long	unit, len;
	int		i, mf;

	char*	taimage = NULL;
	char*	outfile = NULL;
	long	unittoread = -1;
	int		hexdump = 0;
	int		rc = 5;

	--argc;
	argv++;
	while(argc > 0){
		char *arg = argv[0];
		--argc;
		argv++;
		if (!strcmp(arg, "-q"))
			readta_quiet = 1;
		else if (!strcmp(arg, "-h"))
			hexdump = 1;
		else if (argc >= 1) {
			char *val = argv[0];
			--argc;
			argv++;
			if (!strcmp(arg, "-o"))
				outfile = val;
			else if (!strcmp(arg, "-i"))
				taimage = val;
			else if (!strcmp(arg, "-u")) {
				if (val[0] == '0' && val[1] == 'x')
					unittoread = strtoul(val+2, 0, 16);
				else
					unittoread = strtoul(val, 0, 10);
			}
		} else {
			return readta_usage();
		}
	}

	if (!taimage || unittoread == -1)
		return readta_usage();

	f_readta = fopen(taimage, "rb");
	if (f_readta == NULL)
		readta_die(2, "Can't open file %s\n", taimage);

	fseek(f_readta, 0, SEEK_END);
	tasize = ftell(f_readta);
	fseek(f_readta, 0, SEEK_SET);

	TA = (unsigned char*)malloc(tasize);
	if (TA == NULL)
		readta_die(3, "Out of memory");

	fread(TA, 1, tasize, f_readta);
	fclose(f_readta);
	f_readta = NULL;

	mf = 0;
	pos = 0;
	while (pos<tasize-sizeof(magic)) {

		if (pos > 0x7ff00)
			pos = pos;

		if (!mf) {
			/* Search for magic */
			if (memcmp(TA+pos, magic, sizeof(magic))) {
				pos++;
				continue;
			}

			/* Magic found */
			pos += sizeof(magic);
			pos += 8;
			mf = 1;
		}

		if (memcmp(TA+pos+8, magic, sizeof(magic))) {
			mf = 0;
			continue;
		}

		for (unit=0,i=0; i<4; i++)
			unit += TA[pos++]<<(i*8);

		for (len=0,i=0; i<4; i++)
			len += TA[pos++]<<(i*8);

		if ((pos & 0x1ffff) == 0) { // Partition boundary
			mf = 0;
			continue;
		}

		pos += sizeof(magic);
		pos += 4;

		if (len < 0) {
			mf = 0;
			continue;
		}

		if (unittoread != unit) {
			pos += len;
			pos = (pos + 3) & ~3;
			continue;
		}

		if (outfile) {
			f_readta = fopen(outfile ,"wb");
			if (f_readta == NULL)
				readta_die(2, "Can't open output file %s\n", outfile);
		} else
			f_readta = stdout;

		if (hexdump == 0)
			fwrite(TA+pos, 1, len, f_readta);
		else
			for (i=0; i<len; i++) {
				if ((i & 0xf) != 0)
					fwrite(" ", 1, 1, f_readta); 
				else if (i != 0)
					fwrite("\n", 1, 1, f_readta); 
				fprintf(f_readta, "%02X", TA[pos+i]);
			}

		if (outfile)
			fclose(f_readta);

		rc = 0;
		break;
	}

	free(TA);
	return rc;
}
